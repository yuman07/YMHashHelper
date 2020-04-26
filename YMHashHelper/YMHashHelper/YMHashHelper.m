//
//  YMHashHelper.m
//  YMHashHelper
//
//  Created by yuman01 on 2018/9/13.
//  Copyright © 2018年 yuman. All rights reserved.
//

#import "YMHashHelper.h"
#import <CommonCrypto/CommonDigest.h>

#define CHECK_STRING_VALID(_STRING_) \
({ id __a__ = (_STRING_); (__a__ && [__a__ isKindOfClass:[NSString class]] && (((NSString *)__a__).length > 0)); })

#define CHECK_DATA_VALID(_DATA_) \
({ id __a__ = (_DATA_); (__a__ && [__a__ isKindOfClass:[NSData class]] && (((NSData *)__a__).length > 0)); })

typedef NS_ENUM(NSInteger, YMHashHelperType) {
    YMHashHelperTypeNone,
    YMHashHelperTypeMD5,
    YMHashHelperTypeSHA1,
    YMHashHelperTypeSHA256,
    YMHashHelperTypeSHA512
};

static const NSUInteger kDefaultChunkSizeForReadingData = 16384;

@interface YMHashHelper ()

@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, assign) YMHashHelperType hashType;
@property (nonatomic, assign) BOOL isCompleted;
@property (nonatomic, strong) NSString *resultString;

@property (nonatomic, assign) CC_MD5_CTX md5CTX;
@property (nonatomic, assign) CC_SHA1_CTX sha1CTX;
@property (nonatomic, assign) CC_SHA256_CTX sha256CTX;
@property (nonatomic, assign) CC_SHA512_CTX sha512CTX;

@end

@implementation YMHashHelper

- (instancetype)init
{
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create([[NSString stringWithFormat:@"com.YMHashHelper.%p", self] UTF8String], DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

#pragma mark --- oneShot hash

+ (NSString *)md5WithString:(NSString *)string
{
    if (!CHECK_STRING_VALID(string)) {
        return nil;
    }
    return [self md5WithData:[string dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSString *)sha1WithString:(NSString *)string
{
    if (!CHECK_STRING_VALID(string)) {
        return nil;
    }
    return [self sha1WithData:[string dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSString *)sha256WithString:(NSString *)string
{
    if (!CHECK_STRING_VALID(string)) {
        return nil;
    }
    return [self sha256WithData:[string dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSString *)sha512WithString:(NSString *)string
{
    if (!CHECK_STRING_VALID(string)) {
        return nil;
    }
    return [self sha512WithData:[string dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSString *)md5WithData:(NSData *)data
{
    if (!CHECK_DATA_VALID(data)) {
        return nil;
    }
    
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    CC_MD5(data.bytes, (CC_LONG)data.length, result);
    for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [hash copy];
}

+ (NSString *)sha1WithData:(NSData *)data
{
    if (!CHECK_DATA_VALID(data)) {
        return nil;
    }
    
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    CC_SHA1(data.bytes, (CC_LONG)data.length, result);
    for (NSUInteger i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [hash copy];
}

+ (NSString *)sha256WithData:(NSData *)data
{
    if (!CHECK_DATA_VALID(data)) {
        return nil;
    }
    
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    CC_SHA256(data.bytes, (CC_LONG)data.length, result);
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [hash copy];
}

+ (NSString *)sha512WithData:(NSData *)data
{
    if (!CHECK_DATA_VALID(data)) {
        return nil;
    }
    
    unsigned char result[CC_SHA512_DIGEST_LENGTH];
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    CC_SHA512(data.bytes, (CC_LONG)data.length, result);
    for (NSUInteger i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [hash copy];
}

+ (NSString *)md5WithFilePath:(NSString *)filePath
{
    if (!CHECK_STRING_VALID(filePath)) {
        return nil;
    }
    
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    if (!handle) {
        return nil;
    }
    
    CC_MD5_CTX md5;
    CC_MD5_Init(&md5);
    for (;;) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            if (fileData.length == 0) break;
            CC_MD5_Update(&md5, fileData.bytes, (CC_LONG)fileData.length);
        }
    }
    [handle closeFile];
    
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(result, &md5);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [hash copy];
}

+ (NSString *)sha1WithFilePath:(NSString *)filePath
{
    if (!CHECK_STRING_VALID(filePath)) {
        return nil;
    }
    
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    if (!handle) {
        return nil;
    }
    
    CC_SHA1_CTX sha1;
    CC_SHA1_Init(&sha1);
    for (;;) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            if (fileData.length == 0) break;
            CC_SHA1_Update(&sha1, fileData.bytes, (CC_LONG)fileData.length);
        }
    }
    [handle closeFile];
    
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1_Final(result, &sha1);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [hash copy];
}

+ (NSString *)sha256WithFilePath:(NSString *)filePath
{
    if (!CHECK_STRING_VALID(filePath)) {
        return nil;
    }
    
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    if (!handle) {
        return nil;
    }
    
    CC_SHA256_CTX sha256;
    CC_SHA256_Init(&sha256);
    for (;;) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            if (fileData.length == 0) break;
            CC_SHA256_Update(&sha256, fileData.bytes, (CC_LONG)fileData.length);
        }
    }
    [handle closeFile];
    
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(result, &sha256);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [hash copy];
}

+ (NSString *)sha512WithFilePath:(NSString *)filePath
{
    if (!CHECK_STRING_VALID(filePath)) {
        return nil;
    }
    
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    if (!handle) {
        return nil;
    }
    
    CC_SHA512_CTX sha512;
    CC_SHA512_Init(&sha512);
    for (;;) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            if (fileData.length == 0) break;
            CC_SHA512_Update(&sha512, fileData.bytes, (CC_LONG)fileData.length);
        }
    }
    [handle closeFile];
    
    unsigned char result[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_Final(result, &sha512);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [hash copy];
}

#pragma mark --- stream hash

- (void)md5UpdateWithData:(NSData *)data
{
    dispatch_async(self.queue, ^{
        if (self.isCompleted) {
            return;
        }
        
        if (!CHECK_DATA_VALID(data)) {
            return;
        }
        
        if (self.hashType == YMHashHelperTypeNone) {
            self.hashType = YMHashHelperTypeMD5;
            CC_MD5_Init(&self->_md5CTX);
        }
        
        if (self.hashType != YMHashHelperTypeMD5) {
            self.isCompleted = YES;
            return;
        }
        
        CC_MD5_Update(&self->_md5CTX, data.bytes, (CC_LONG)data.length);
    });
}

- (void)sha1UpdateWithData:(NSData *)data
{
    dispatch_async(self.queue, ^{
        if (self.isCompleted) {
            return;
        }
        
        if (!CHECK_DATA_VALID(data)) {
            return;
        }
        
        if (self.hashType == YMHashHelperTypeNone) {
            self.hashType = YMHashHelperTypeSHA1;
            CC_SHA1_Init(&self->_sha1CTX);
        }
        
        if (self.hashType != YMHashHelperTypeSHA1) {
            self.isCompleted = YES;
            return;
        }
        
        CC_SHA1_Update(&self->_sha1CTX, data.bytes, (CC_LONG)data.length);
    });
}

- (void)sha256UpdateWithData:(NSData *)data
{
    dispatch_async(self.queue, ^{
        if (self.isCompleted) {
            return;
        }
        
        if (!CHECK_DATA_VALID(data)) {
            return;
        }
        
        if (self.hashType == YMHashHelperTypeNone) {
            self.hashType = YMHashHelperTypeSHA256;
            CC_SHA256_Init(&self->_sha256CTX);
        }
        
        if (self.hashType != YMHashHelperTypeSHA256) {
            self.isCompleted = YES;
            return;
        }
        
        CC_SHA256_Update(&self->_sha256CTX, data.bytes, (CC_LONG)data.length);
    });
}

- (void)sha512UpdateWithData:(NSData *)data
{
    dispatch_async(self.queue, ^{
        if (self.isCompleted) {
            return;
        }
        
        if (!CHECK_DATA_VALID(data)) {
            return;
        }
        
        if (self.hashType == YMHashHelperTypeNone) {
            self.hashType = YMHashHelperTypeSHA512;
            CC_SHA512_Init(&self->_sha512CTX);
        }
        
        if (self.hashType != YMHashHelperTypeSHA512) {
            self.isCompleted = YES;
            return;
        }
        
        CC_SHA512_Update(&self->_sha512CTX, data.bytes, (CC_LONG)data.length);
    });
}

- (NSString *)hashTaskComplete
{
    dispatch_sync(self.queue, ^{
        if (self.isCompleted) {
            return;
        }
        
        self.isCompleted = YES;
        
        switch (self.hashType) {
            case YMHashHelperTypeMD5: {
                unsigned char result[CC_MD5_DIGEST_LENGTH];
                CC_MD5_Final(result, &self->_md5CTX);
                NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
                for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
                    [hash appendFormat:@"%02x", result[i]];
                }
                self.resultString = [hash copy];
                break;
            }
                
            case YMHashHelperTypeSHA1: {
                unsigned char result[CC_SHA1_DIGEST_LENGTH];
                CC_SHA1_Final(result, &self->_sha1CTX);
                NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
                for (NSUInteger i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
                    [hash appendFormat:@"%02x", result[i]];
                }
                self.resultString = [hash copy];
                break;
            }
                
            case YMHashHelperTypeSHA256: {
                unsigned char result[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256_Final(result, &self->_sha256CTX);
                NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
                for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
                    [hash appendFormat:@"%02x", result[i]];
                }
                self.resultString = [hash copy];
                break;
            }
                
            case YMHashHelperTypeSHA512: {
                unsigned char result[CC_SHA512_DIGEST_LENGTH];
                CC_SHA512_Final(result, &self->_sha512CTX);
                NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
                for (NSUInteger i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
                    [hash appendFormat:@"%02x", result[i]];
                }
                self.resultString = [hash copy];
                break;
            }
                
            default:
                break;
        }
    });
    
    return self.resultString;
}

- (void)reset
{
    dispatch_async(self.queue, ^{
        self.isCompleted = NO;
        self.hashType = YMHashHelperTypeNone;
        self.resultString = nil;
    });
}

@end
