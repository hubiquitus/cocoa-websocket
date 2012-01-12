//
//  WebSocket.m
//
//  Originally created for Zimt by Esad Hajdarevic on 2/14/10.
//  Copyright 2010 OpenResearch Software Development OG. All rights reserved.
//
//  Erich Ocean made the code more generic.
//
//  Tobias Rodäbel implemented support for draft-hixie-thewebsocketprotocol-76.
//  Adam Ernst implemented support for the final WebSocket RFC.
//

#import "WebSocket.h"
#import "AsyncSocket.h"

#import <CommonCrypto/CommonDigest.h>

// Set this to 1 if you are running in secure mode on a box without a valid cert
#define WEBSOCKET_DEV_MODE 0

NSString * const WebSocketErrorDomain = @"WebSocketErrorDomain";
NSString * const WebSocketException   = @"WebSocketException";

enum {
    WebSocketTagHandshake = 0,
    WebSocketTagHeader = 1,
    WebSocketTagPayloadLength = 2,
    WebSocketTagMessage = 3,
};

typedef enum {
    WebSocketOpCodeContinuationFrame = 0,
    WebSocketOpCodeTextFrame = 1,
    WebSocketOpCodeBinaryFrame = 2,
    WebSocketOpCodeConnectionCloseFrame = 3,
    WebSocketOpCodePingFrame = 9,
    WebSocketOpCodePongFrame = 10,
} WebSocketOpCode;

typedef uint8_t WebSocketFrameHeader[2];

static inline WebSocketOpCode WebSocketOpCodeFromHeader(WebSocketFrameHeader header) {
    return (WebSocketOpCode) (header[0] & 0xf);
}

static inline uint8_t WebSocketPayloadLengthFromHeader(WebSocketFrameHeader header) {
    return header[1] & 0x7f;
}

static inline BOOL WebSocketFINFromHeader(WebSocketFrameHeader header) {
    return ((header[0] >> 7) & 0x1) != 0;
}

static inline BOOL WebSocketMaskFromHeader(WebSocketFrameHeader header) {
    return ((header[1] >> 7) & 0x1) != 0;
}

// 16 random bytes
#define SEC_KEY_SEGMENT_COUNT 4
struct WebSocketKey {
  uint32_t segments[SEC_KEY_SEGMENT_COUNT];
};

#define HANDSHAKE_REQUEST @"GET %@ HTTP/1.1\r\n" \
                           "Host: %@%@\r\n" \
                           "Upgrade: websocket\r\n" \
                           "Connection: Upgrade\r\n" \
                           "Sec-WebSocket-Key: %@\r\n" \
                           "Origin: %@\r\n" \
                           "Sec-WebSocket-Version: 13\r\n\r\n"

@interface WebSocket () {
    struct {
        WebSocketOpCode opCode;
        BOOL fin;
        NSMutableData *data;
    } currentFrame;
}
@property(nonatomic,readwrite) WebSocketState state;
@property(nonatomic,retain) NSString *expectedChallenge;
@end


@implementation WebSocket

@synthesize delegate, url, origin, state, expectedChallenge, runLoopModes, secure;

#pragma mark Initializers

+ (id)webSocketWithURLString:(NSString*)urlString delegate:(id<WebSocketDelegate>)aDelegate {
    return [[[WebSocket alloc] initWithURLString:urlString delegate:aDelegate] autorelease];
}

- (id)initWithURLString:(NSString *)urlString delegate:(id<WebSocketDelegate>)aDelegate {
    self = [super init];
    if (self) {
        self.delegate = aDelegate;
        url = [[NSURL URLWithString:urlString] retain];
        if (![url.scheme isEqualToString:@"ws"] && ![url.scheme isEqualToString:@"wss"]) {
          [NSException raise:WebSocketException format:@"Unsupported protocol %@", url.scheme];
        }
        if ([url.scheme isEqualToString:@"wss"]) {
          secure = YES;
        }
        socket = [[AsyncSocket alloc] initWithDelegate:self];
        self.runLoopModes = [NSArray arrayWithObjects:NSRunLoopCommonModes, nil];
        
        currentFrame.data = [[NSMutableData alloc] init];
    }
    return self;
}

#pragma mark Delegate dispatch methods

- (void)_dispatchFailure:(NSError *)error {
    if([delegate respondsToSelector:@selector(webSocket:didFailWithError:)]) {
        [delegate webSocket:self didFailWithError:error];
    }
}

- (void)_dispatchClosed {
    if ([delegate respondsToSelector:@selector(webSocketDidClose:)]) {
        [delegate webSocketDidClose:self];
    }
}

- (void)_dispatchOpened {
    if ([delegate respondsToSelector:@selector(webSocketDidOpen:)]) {
        [delegate webSocketDidOpen:self];
    }
}

- (void)_dispatchTextMessageReceived:(NSString*)message {
    NSLog(@"Message %@", message);
    if ([delegate respondsToSelector:@selector(webSocket:didReceiveTextMessage:)]) {
        [delegate webSocket:self didReceiveTextMessage:message];
    } else if ([delegate respondsToSelector:@selector(webSocket:didReceiveMessage:)]) {
        // Fall back to old, deprecated delegate selector.
        [delegate webSocket:self didReceiveMessage:message];
    }
}

- (void)_dispatchBinaryMessageReceived:(NSData *)message {
    if ([delegate respondsToSelector:@selector(webSocket:didReceiveBinaryMessage:)]) {
        [delegate webSocket:self didReceiveBinaryMessage:message];
    }
}

- (void)_dispatchMessageSent {
    if ([delegate respondsToSelector:@selector(webSocketDidSendMessage:)]) {
        [delegate webSocketDidSendMessage:self];
    }
}

- (void)_dispatchSecured {
    if ([delegate respondsToSelector:@selector(webSocketDidSecure:)]) {
      [delegate webSocketDidSecure:self];
    }
}

#pragma mark Private

- (void)_readNextMessage {
    [socket readDataToLength:2 withTimeout:-1 tag:WebSocketTagHeader];
}

- (struct WebSocketKey)_makeKey {
    struct WebSocketKey seckey;
    for (int i = 0; i < SEC_KEY_SEGMENT_COUNT; i++) {
        seckey.segments[i] = arc4random();
    }
    return seckey;
}

- (NSError *)_makeError:(int)code underlyingError:(NSError *)underlyingError {
    NSDictionary *userInfo = nil;
    if (underlyingError) {
        userInfo = [NSDictionary dictionaryWithObject:underlyingError forKey:NSUnderlyingErrorKey];
    }
    return [NSError errorWithDomain:WebSocketErrorDomain code:code userInfo:userInfo];
}

#pragma mark Public interface

- (void)close {
    [socket disconnect];
}

- (void)open {
    if ([self state] == WebSocketStateDisconnected) {
        if (secure) {
            NSDictionary *settings = nil;
            if (WEBSOCKET_DEV_MODE) {
                settings = [NSDictionary dictionaryWithObject:[NSNumber numberWithBool:YES]
                                                       forKey:(NSString *)kCFStreamSSLAllowsAnyRoot];
            }
            [socket startTLS:settings];
        }

        [socket connectToHost:url.host onPort:[url.port intValue] withTimeout:5 error:nil];
        if (runLoopModes) [socket setRunLoopModes:runLoopModes];
    }
}

- (void)send:(NSString*)message {
    /*NSMutableData* data = [NSMutableData data];
    [data appendBytes:"\x00" length:1];
    [data appendData:[message dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendBytes:"\xFF" length:1];
    [socket writeData:data withTimeout:-1 tag:WebSocketTagMessage];*/
}

- (BOOL)connected {
    // Backwards compatibility only.
    return [self state] == WebSocketStateConnected;
}

#pragma mark AsyncSocket delegate methods

- (BOOL)onSocketWillConnect:(AsyncSocket *)sock {
  if (secure && WEBSOCKET_DEV_MODE) {
    // Connecting to a secure server
    NSMutableDictionary * settings = [NSMutableDictionary dictionaryWithCapacity:2];

    // Use the highest possible security
    [settings setObject:(NSString *)kCFStreamSocketSecurityLevelNegotiatedSSL
                 forKey:(NSString *)kCFStreamSSLLevel];

    // Allow self-signed certificates
    [settings setObject:[NSNumber numberWithBool:YES]
                 forKey:(NSString *)kCFStreamSSLAllowsAnyRoot];

    CFReadStreamSetProperty([sock getCFReadStream],
                            kCFStreamPropertySSLSettings, (CFDictionaryRef)settings);
    CFWriteStreamSetProperty([sock getCFWriteStream],
                             kCFStreamPropertySSLSettings, (CFDictionaryRef)settings);
  }

  return YES;
}

- (void)onSocketDidSecure:(AsyncSocket *)sock {
  [self _dispatchSecured];
}

- (void)onSocketDidDisconnect:(AsyncSocket *)sock {
    BOOL wasConnected = ([self state] == WebSocketStateConnected);
    [self setState:WebSocketStateDisconnected];
    
    // Only dispatch the websocket closed message if it previously opened
    // (completed the handshake). If it never opened, this is probably a 
    // connection timeout error.
    if (wasConnected) [self _dispatchClosed];
}

- (void)onSocket:(AsyncSocket *)sock willDisconnectWithError:(NSError *)err {
    if ([self state] == WebSocketStateConnecting) {
        [self _dispatchFailure:[self _makeError:WebSocketErrorConnectionFailed underlyingError:err]];
    } else {
        [self _dispatchFailure:err];
    }
}

// Borrowed from AEURLConnection
NSString * WSBase64EncodedStringFromData(NSData *data) {
  NSUInteger length = [data length];
  NSMutableData *mutableData = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
  
  uint8_t *input = (uint8_t *)[data bytes];
  uint8_t *output = (uint8_t *)[mutableData mutableBytes];
  
  for (NSUInteger i = 0; i < length; i += 3) {
    NSUInteger value = 0;
    for (NSUInteger j = i; j < (i + 3); j++) {
      value <<= 8;
      if (j < length) {
        value |= (0xFF & input[j]); 
      }
    }
    
    static uint8_t const kAFBase64EncodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    NSUInteger idx = (i / 3) * 4;
    output[idx + 0] = kAFBase64EncodingTable[(value >> 18) & 0x3F];
    output[idx + 1] = kAFBase64EncodingTable[(value >> 12) & 0x3F];
    output[idx + 2] = (i + 1) < length ? kAFBase64EncodingTable[(value >> 6)  & 0x3F] : '=';
    output[idx + 3] = (i + 2) < length ? kAFBase64EncodingTable[(value >> 0)  & 0x3F] : '=';
  }
  
  return [[[NSString alloc] initWithData:mutableData encoding:NSASCIIStringEncoding] autorelease];
}

- (void)onSocket:(AsyncSocket *)sock didConnectToHost:(NSString *)host port:(UInt16)port {

    NSString *requestOrigin = (self.origin) ? self.origin : [NSString stringWithFormat:@"http://%@", url.host];

    NSString *requestPath = (url.query) ? [NSString stringWithFormat:@"%@?%@", url.path, url.query] : url.path;

    struct WebSocketKey seckey = [self _makeKey];
    NSString *base64Key = WSBase64EncodedStringFromData([NSData dataWithBytes:&seckey length:16]);

    NSData *keyWithGUID = [[base64Key stringByAppendingString:@"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"] dataUsingEncoding:NSASCIIStringEncoding];
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([keyWithGUID bytes], [keyWithGUID length], digest);
    NSData *expectedChallengeData = [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
    
    self.expectedChallenge = WSBase64EncodedStringFromData(expectedChallengeData);

    NSString *headers = [NSString stringWithFormat:
                         HANDSHAKE_REQUEST,
                         requestPath,
                         url.host,
                         ((secure && [url.port intValue] != 443) ||
                          (!secure && [url.port intValue] != 80)) ?
                         [NSString stringWithFormat:@":%d", [url.port intValue]] : @"",
                         base64Key,
                         requestOrigin];

    [socket writeData:[NSMutableData dataWithData:[headers dataUsingEncoding:NSASCIIStringEncoding]] 
          withTimeout:-1 
                  tag:WebSocketTagHandshake];
}

- (void)onSocket:(AsyncSocket *)sock didWriteDataWithTag:(long)tag {
    switch (tag) {
        case WebSocketTagHandshake:
            [sock readDataToData:[@"\r\n\r\n" dataUsingEncoding:NSASCIIStringEncoding] withTimeout:5 tag:WebSocketTagHandshake];
            break;

        case WebSocketTagMessage:
            [self _dispatchMessageSent];
            break;

        default:
            break;
    }
}

- (void)onSocket:(AsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {

    if (tag == WebSocketTagHandshake) {

        NSString *upgrade = nil;
        NSString *connection = nil;
        NSString *accept = nil;
        UInt32 statusCode = 0;

        CFHTTPMessageRef message = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, FALSE);
        
        if (!message || !CFHTTPMessageAppendBytes(message, [data bytes], [data length])) {
            [self _dispatchFailure:[self _makeError:WebSocketErrorHandshakeFailed underlyingError:nil]];
            if (message) CFRelease(message);
            return;
        }

        if (CFHTTPMessageIsHeaderComplete(message)) {
            upgrade = [(NSString *) CFHTTPMessageCopyHeaderFieldValue(message, CFSTR("Upgrade")) autorelease];
            connection = [(NSString *) CFHTTPMessageCopyHeaderFieldValue(message, CFSTR("Connection")) autorelease];
            accept = [(NSString *) CFHTTPMessageCopyHeaderFieldValue(message, CFSTR("Sec-WebSocket-Accept")) autorelease];
            statusCode = (UInt32)CFHTTPMessageGetResponseStatusCode(message);
        }
        CFRelease(message);

        if (statusCode == 101 && [upgrade isEqualToString:@"websocket"] && [connection isEqualToString:@"Upgrade"] && [accept isEqualToString:self.expectedChallenge]) {
            [self setState:WebSocketStateConnected];
            [self _dispatchOpened];
            [self _readNextMessage];
        } else {
            [self _dispatchFailure:[self _makeError:WebSocketErrorHandshakeFailed underlyingError:nil]];
        }

    } else if (tag == WebSocketTagHeader) {

        WebSocketFrameHeader header;
        [data getBytes:&header length:2];

        WebSocketOpCode code = WebSocketOpCodeFromHeader(header);
        uint8_t length = WebSocketPayloadLengthFromHeader(header);
        BOOL fin = WebSocketFINFromHeader(header);
        BOOL mask = WebSocketMaskFromHeader(header);
        // TODO terminate with error if mask is 1.
        // TODO terminate with error if FIN is 0 and code is a control (>= 8).
        
        currentFrame.opCode = code;
        currentFrame.fin = fin;
        
        if (length == 126) {
            [sock readDataToLength:2 withTimeout:-1 tag:WebSocketTagPayloadLength];
        } else if (length == 127) {
            [sock readDataToLength:8 withTimeout:-1 tag:WebSocketTagPayloadLength];
        } else if (length == 0) {
            // TODO process message as is with no data
        } else {
            [sock readDataToLength:length withTimeout:-1 tag:WebSocketTagMessage];
        }

    } else if (tag == WebSocketTagPayloadLength) {

        uint64_t length;
        if ([data length] == 2) {
            uint16_t length_16;
            [data getBytes:&length_16];
            length = ntohs(length_16);
        } else if ([data length] == 8) {
            uint64_t length_64;
            [data getBytes:&length_64];
            // TODO swap
        }
        // TODO: this is vulnerable to overflow. CFIndex (length) is a currently
        // a signed 32-bit value.
        [sock readDataToLength:length withTimeout:-1 tag:WebSocketTagMessage];

    } else if (tag == WebSocketTagMessage) {

        [currentFrame.data appendData:data];
        
        if (currentFrame.fin) {
            switch (currentFrame.opCode) {
                case WebSocketOpCodeTextFrame:
                    [self _dispatchTextMessageReceived:[[[NSString alloc] initWithData:currentFrame.data encoding:NSUTF8StringEncoding] autorelease]];
                    break;
                case WebSocketOpCodeBinaryFrame:
                    [self _dispatchBinaryMessageReceived:currentFrame.data];
                    break;
                case WebSocketOpCodePingFrame:
                    // TODO send pong
                    break;
                case WebSocketOpCodePongFrame:
                    // No-op; we don't send pings.
                    break;
                case WebSocketOpCodeConnectionCloseFrame:
                    // TODO close connection;
                    break;
                case WebSocketOpCodeContinuationFrame:
                default:
                    // TODO error
                    break;
            }
            [self _readNextMessage];
        }

    }
}

#pragma mark Destructor

- (void)dealloc {
    socket.delegate = nil;
    [socket disconnect];
    [socket release];
    [expectedChallenge release];
    [runLoopModes release];
    [url release];
    [currentFrame.data release];
    [super dealloc];
}

@end
