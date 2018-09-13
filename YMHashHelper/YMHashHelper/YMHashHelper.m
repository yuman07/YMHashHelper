//
//  YMHashHelper.m
//  YMHashHelper
//
//  Created by yuman01 on 2018/9/13.
//  Copyright © 2018年 yuman. All rights reserved.
//

#import "YMHashHelper.h"
#import <CommonCrypto/CommonDigest.h>

static const NSUInteger kDefaultChunkSizeForReadingData = 16384;

@implementation YMHashHelper

+ (NSString *)hashString:(NSString *)string WithHashType:(YMHashHelperType)type
{
    if (!string || ![string isKindOfClass:[NSString class]] || string.length == 0) {
        return nil;
    }
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [self hashData:data WithHashType:type];
}

+ (NSString *)hashData:(NSData *)data WithHashType:(YMHashHelperType)type
{
    if (!data || ![data isKindOfClass:[NSData class]] || data.length == 0) {
        return nil;
    }
    
    NSMutableString *hash = nil;
    switch (type) {
        case YMHashHelperTypeMD5: {
            uint8_t result[CC_MD5_DIGEST_LENGTH];
            hash = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
            CC_MD5(data.bytes, (CC_LONG)data.length, result);
            for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
                [hash appendFormat:@"%02x", result[i]];
            }
            break;
        }
            
        case YMHashHelperTypeSHA1: {
            uint8_t result[CC_SHA1_DIGEST_LENGTH];
            hash = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
            CC_SHA1(data.bytes, (CC_LONG)data.length, result);
            for (NSUInteger i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
                [hash appendFormat:@"%02x", result[i]];
            }
            break;
        }
            
        case YMHashHelperTypeSHA256: {
            uint8_t result[CC_SHA256_DIGEST_LENGTH];
            hash = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
            CC_SHA256(data.bytes, (CC_LONG)data.length, result);
            for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
                [hash appendFormat:@"%02x", result[i]];
            }
            break;
        }
            
        case YMHashHelperTypeSHA512: {
            uint8_t result[CC_SHA512_DIGEST_LENGTH];
            hash = [[NSMutableString alloc] initWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
            CC_SHA512(data.bytes, (CC_LONG)data.length, result);
            for (NSUInteger i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
                [hash appendFormat:@"%02x", result[i]];
            }
            break;
        }
            
        default:
            break;
    }
    
    return [[hash lowercaseString] copy];
}

+ (NSString *)hashFile:(NSString *)filePath WithHashType:(YMHashHelperType)type
{
    if (!filePath || ![filePath isKindOfClass:[NSString class]] || filePath.length == 0) {
        return nil;
    }
    
    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    if (!handle) {
        return nil;
    }
    
    NSString *hash = nil;
    switch (type) {
        case YMHashHelperTypeMD5:
            hash = [self md5WithFileHandle:handle];
            break;
            
        case YMHashHelperTypeSHA1:
            hash = [self sha1WithFileHandle:handle];
            break;
            
        case YMHashHelperTypeSHA256:
            hash = [self sha256WithFileHandle:handle];
            break;
            
        case YMHashHelperTypeSHA512:
            hash = [self sha512WithFileHandle:handle];
            break;
            
        default:
            break;
    }
    return hash;
}

+ (NSString *)md5WithFileHandle:(NSFileHandle *)handle
{
    CC_MD5_CTX md5;
    CC_MD5_Init(&md5);
    BOOL hasMoreData = YES;
    while(hasMoreData) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            CC_MD5_Update(&md5, [fileData bytes], (CC_LONG)[fileData length]);
            if(fileData.length == 0) hasMoreData = NO;
        }
    }
    uint8_t result[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(result, &md5);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    [handle closeFile];
    return [[hash lowercaseString] copy];
}

+ (NSString *)sha1WithFileHandle:(NSFileHandle *)handle
{
    CC_SHA1_CTX sha1;
    CC_SHA1_Init(&sha1);
    BOOL hasMoreData = YES;
    while(hasMoreData) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            CC_SHA1_Update(&sha1, [fileData bytes], (CC_LONG)[fileData length]);
            if(fileData.length == 0) hasMoreData = NO;
        }
    }
    uint8_t result[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1_Final(result, &sha1);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    [handle closeFile];
    return [[hash lowercaseString] copy];
}

+ (NSString *)sha256WithFileHandle:(NSFileHandle *)handle
{
    CC_SHA256_CTX sha256;
    CC_SHA256_Init(&sha256);
    BOOL hasMoreData = YES;
    while(hasMoreData) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            CC_SHA256_Update(&sha256, [fileData bytes], (CC_LONG)[fileData length]);
            if(fileData.length == 0) hasMoreData = NO;
        }
    }
    uint8_t result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(result, &sha256);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    [handle closeFile];
    return [[hash lowercaseString] copy];
}

+ (NSString *)sha512WithFileHandle:(NSFileHandle *)handle
{
    CC_SHA512_CTX sha512;
    CC_SHA512_Init(&sha512);
    BOOL hasMoreData = YES;
    while(hasMoreData) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            CC_SHA512_Update(&sha512, [fileData bytes], (CC_LONG)[fileData length]);
            if(fileData.length == 0) hasMoreData = NO;
        }
    }
    uint8_t result[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_Final(result, &sha512);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    [handle closeFile];
    return [[hash lowercaseString] copy];
}

@end
