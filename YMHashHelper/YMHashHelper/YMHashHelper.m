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
({ NSString *__v__ = (_STRING_); (__v__ && [__v__ isKindOfClass:[NSString class]] && (__v__.length > 0)); })

#define CHECK_DATA_VALID(_DATA_) \
({ NSData *__v__ = (_DATA_); (__v__ && [__v__ isKindOfClass:[NSData class]] && (__v__.length > 0)); })

static const NSUInteger kDefaultChunkSizeForReadingData = 16384;

@implementation YMHashHelper

+ (NSString *)md5WithString:(NSString *)string
{
    if (!CHECK_STRING_VALID(string)) {
        return nil;
    }
    
    const char *cStr = string.UTF8String;
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(cStr, (CC_LONG)strlen(cStr), result);
    
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [[hash lowercaseString] copy];
}

+ (NSString *)sha1WithString:(NSString *)string
{
    if (!CHECK_STRING_VALID(string)) {
        return nil;
    }
    
    const char *cStr = string.UTF8String;
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(cStr, (CC_LONG)strlen(cStr), result);
    
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [[hash lowercaseString] copy];
}

+ (NSString *)sha256WithString:(NSString *)string
{
    if (!CHECK_STRING_VALID(string)) {
        return nil;
    }
    
    const char *cStr = string.UTF8String;
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cStr, (CC_LONG)strlen(cStr), result);
    
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [[hash lowercaseString] copy];
}

+ (NSString *)sha512WithString:(NSString *)string
{
    if (!CHECK_STRING_VALID(string)) {
        return nil;
    }
    
    const char *cStr = string.UTF8String;
    unsigned char result[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(cStr, (CC_LONG)strlen(cStr), result);
    
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [[hash lowercaseString] copy];
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
    
    return [[hash lowercaseString] copy];
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
    
    return [[hash lowercaseString] copy];
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
    
    return [[hash lowercaseString] copy];
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
    
    return [[hash lowercaseString] copy];
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
    while(YES) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            if (!CHECK_DATA_VALID(fileData)) break;
            CC_MD5_Update(&md5, [fileData bytes], (CC_LONG)[fileData length]);
        }
    }
    [handle closeFile];
    
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5_Final(result, &md5);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [[hash lowercaseString] copy];
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
    while(YES) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            if (!CHECK_DATA_VALID(fileData)) break;
            CC_SHA1_Update(&sha1, [fileData bytes], (CC_LONG)[fileData length]);
        }
    }
    [handle closeFile];
    
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1_Final(result, &sha1);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [[hash lowercaseString] copy];
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
    while(YES) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            if (!CHECK_DATA_VALID(fileData)) break;
            CC_SHA256_Update(&sha256, [fileData bytes], (CC_LONG)[fileData length]);
        }
    }
    [handle closeFile];
    
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(result, &sha256);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [[hash lowercaseString] copy];
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
    BOOL hasMoreData = YES;
    while(hasMoreData) {
        @autoreleasepool {
            NSData *fileData = [handle readDataOfLength:kDefaultChunkSizeForReadingData];
            if (!CHECK_DATA_VALID(fileData)) break;
            CC_SHA512_Update(&sha512, [fileData bytes], (CC_LONG)[fileData length]);
        }
    }
    [handle closeFile];
    
    unsigned char result[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512_Final(result, &sha512);
    NSMutableString *hash = [[NSMutableString alloc] initWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    
    return [[hash lowercaseString] copy];
}

@end
