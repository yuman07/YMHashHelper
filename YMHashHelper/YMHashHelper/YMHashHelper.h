//
//  YMHashHelper.h
//  YMHashHelper
//
//  Created by yuman01 on 2018/9/13.
//  Copyright © 2018年 yuman. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, YMHashHelperType) {
    YMHashHelperTypeMD5,
    YMHashHelperTypeSHA1,
    YMHashHelperTypeSHA256,
    YMHashHelperTypeSHA512
};

/**
 用于获得一个字符串/文件/Data的hash值
 如果传入的参数不合法，则返回nil
 返回的哈希字符串均是小写
 */
@interface YMHashHelper : NSObject

+ (NSString *)hashString:(NSString *)string WithHashType:(YMHashHelperType)type;

+ (NSString *)hashFile:(NSString *)filePath WithHashType:(YMHashHelperType)type;

+ (NSString *)hashData:(NSData *)data WithHashType:(YMHashHelperType)type;

@end
