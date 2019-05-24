//
//  YMHashHelper.h
//  YMHashHelper
//
//  Created by yuman01 on 2018/9/13.
//  Copyright © 2018年 yuman. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 用于计算字符串/data/文件的hash值
 如果计算hash失败，则返回nil
 返回的hash字符串均是小写
 */
@interface YMHashHelper : NSObject

// 对字符串进行hash
+ (NSString *)md5WithString:(NSString *)string;
+ (NSString *)sha1WithString:(NSString *)string;
+ (NSString *)sha256WithString:(NSString *)string;
+ (NSString *)sha512WithString:(NSString *)string;

// 对data进行hash
+ (NSString *)md5WithData:(NSData *)data;
+ (NSString *)sha1WithData:(NSData *)data;
+ (NSString *)sha256WithData:(NSData *)data;
+ (NSString *)sha512WithData:(NSData *)data;

// 对文件进行hash
+ (NSString *)md5WithFilePath:(NSString *)filePath;
+ (NSString *)sha1WithFilePath:(NSString *)filePath;
+ (NSString *)sha256WithFilePath:(NSString *)filePath;
+ (NSString *)sha512WithFilePath:(NSString *)filePath;

@end
