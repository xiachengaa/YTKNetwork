//
//  UVLapiAuthInfoBeanBean.h
//  EZViewer
//
//  Created by xiacheng on 2020/1/10.
//  Copyright © 2020 uniview. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "YTKBaseRequest.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, UVLapiRequestAuthType) {
    UVLapiRequestAuthTypeUnknown = 0,
    UVLapiRequestAuthTypeDigest,  //标准Digest
    UVLapiRequestAuthTypeCustomDigest,  //自定义Digest
    UVLapiRequestAuthTypeBasic  //Basic
};


@interface UVLapiAuthInfoBean : NSObject

@property (assign, nonatomic, readwrite) UVLapiRequestAuthType authType;


+ (instancetype)authInfoWithResoponseAllHeaderFields:(NSDictionary *)allHeaderFields;


- (NSString *)digestAuthenticationForRequest:(YTKBaseRequest *)request;


@end

NS_ASSUME_NONNULL_END
