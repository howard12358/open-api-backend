package com.weeds.gateway.filter;

import com.weeds.client.constant.OpenApiReqHeaderConstant;
import com.weeds.client.utils.SignUtils;
import com.weeds.dubboapi.service.InnerInterfaceInfoService;
import com.weeds.dubboapi.service.InnerUserService;
import com.weeds.gateway.constant.RequestHeaderConstant;
import com.weeds.gateway.utils.LogUtils;
import com.weeds.openapi.common.model.entity.InterfaceInfo;
import com.weeds.openapi.common.model.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.dubbo.config.annotation.DubboReference;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Arrays;
import java.util.List;

/**
 * 全局请求过滤器
 *
 * @author weeds
 */
@Configuration
@Slf4j
@Order(value = Ordered.LOWEST_PRECEDENCE)
public class RequestGlobalFilter implements GlobalFilter {
    @DubboReference
    private InnerUserService innerUserService;
    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    /**
     * IP 白名单
     */
    private static final List<String> WHITELIST = Arrays.asList("127.0.0.1", "localhost");
    /**
     * 请求延时时长：5min
     */
    public static final long REQUEST_DELAY_TIME = 60 * 5L;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = LogUtils.handlePreRequestLog(exchange);
        ServerHttpResponse response = exchange.getResponse();
        HttpHeaders headers = request.getHeaders();

        String accessKey = headers.getFirst(OpenApiReqHeaderConstant.ACCESS_KEY);
        String method = headers.getFirst(OpenApiReqHeaderConstant.METHOD_TYPE);
        String apiUrl = headers.getFirst(OpenApiReqHeaderConstant.API_URL);

        // 1. 并行调用两个接口（使用 zip 组合）
        return Mono.zip(
                        // 包装同步调用，放入专门的弹性线程池执行，避免阻塞 Netty
                        Mono.fromCallable(() -> innerUserService.getInvokeUser(accessKey))
                                .subscribeOn(Schedulers.boundedElastic())
                                .onErrorReturn(new User()), // 异常处理：返回空对象防止链条崩掉

                        Mono.fromCallable(() -> innerInterfaceInfoService.getInvokeInterfaceInfo(apiUrl, method))
                                .subscribeOn(Schedulers.boundedElastic())
                                .onErrorReturn(new InterfaceInfo())
                )
                .flatMap(tuple -> {
                    // tuple 里包含了上面两个调用的结果
                    User invokeUser = tuple.getT1();
                    InterfaceInfo invokeInterfaceInfo = tuple.getT2();

                    // 2. 校验用户信息和接口信息
                    if (invokeUser == null || invokeUser.getId() == null ||
                            invokeInterfaceInfo == null || invokeInterfaceInfo.getId() == null) {
                        return handleForbiddenResponse(response);
                    }

                    // 3. 继续执行原有的验证逻辑
                    Mono<Void> verificationMono = verificationRequest(request, response, invokeUser);
                    if (verificationMono != null) {
                        return verificationMono;
                    }

                    // 4. 构建新的 Request 并向下传递
                    ServerHttpRequest mutateReq = request.mutate()
                            .header(RequestHeaderConstant.USER_ID, Long.toString(invokeUser.getId()))
                            .header(RequestHeaderConstant.INTERFACE_ID, Long.toString(invokeInterfaceInfo.getId()))
                            .header(RequestHeaderConstant.TIME_STAMP, Long.toString(System.currentTimeMillis()))
                            .build();

                    return chain.filter(exchange.mutate().request(mutateReq).build());
                });
    }

//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//        ServerHttpRequest request = LogUtils.handlePreRequestLog(exchange);
//        ServerHttpResponse response = exchange.getResponse();
//        // 处理业务
//        // 数据库根据 accessKey 查询用户
//        HttpHeaders headers = request.getHeaders();
//        String accessKey = headers.getFirst(OpenApiReqHeaderConstant.ACCESS_KEY);
//        String method = headers.getFirst(OpenApiReqHeaderConstant.METHOD_TYPE);
//        String apiUrl = headers.getFirst(OpenApiReqHeaderConstant.API_URL);
//        User invokeUser = null;
//        InterfaceInfo invokeInterfaceInfo = null;
//        try {
//            invokeUser = innerUserService.getInvokeUser(accessKey);
//        } catch (Exception e) {
//            log.error("Gateway getInvokeUser error", e);
//        }
//        try {
//            invokeInterfaceInfo = innerInterfaceInfoService.getInvokeInterfaceInfo(apiUrl, method);
//        } catch (Exception e) {
//            log.error("Gateway getInvokeInterfaceInfo error", e);
//        }
//        if (invokeUser == null || invokeInterfaceInfo == null) {
//            return handleForbiddenResponse(response);
//        }
//        // 验证（处理业务）
//        Mono<Void> mono = verificationRequest(request, response, invokeUser);
//        if (mono != null) {
//            return mono;
//        }
//
//        ServerHttpRequest mutateReq = request.mutate()
//                // 添加用户Id、接口Id，方便响应过滤器处理
//                .header(RequestHeaderConstant.USER_ID, Long.toString(invokeUser.getId()))
//                .header(RequestHeaderConstant.INTERFACE_ID, Long.toString(invokeInterfaceInfo.getId()))
//                .header(RequestHeaderConstant.TIME_STAMP, Long.toString(System.currentTimeMillis()))
//                .build();
//        ServerWebExchange mutateExchange = exchange.mutate().request(mutateReq).build();
//        return chain.filter(mutateExchange);
//    }

    /**
     * 处理业务
     *
     * @param request
     * @param response
     * @return
     */
    private Mono<Void> verificationRequest(ServerHttpRequest request,
                                           ServerHttpResponse response,
                                           User invokeUser) {
        // 1.用户发送请求到AP川网关
        // 3.白名单
        String host = request.getURI().getHost();
        if (!WHITELIST.contains(host)) {
            return handleForbiddenResponse(response);
        }
        // 4.用户鉴权（判新ak、sk是否合法）
        HttpHeaders headers = request.getHeaders();
        String nonce = headers.getFirst(OpenApiReqHeaderConstant.NONCE);
        String timestamp = headers.getFirst(OpenApiReqHeaderConstant.TIME_STAMP);
        String sign = headers.getFirst(OpenApiReqHeaderConstant.SIGN);
        String body = headers.getFirst(OpenApiReqHeaderConstant.BODY);
        // 数据库根据 accessKey 查询的用户
        String dbSecretKey = invokeUser.getSecretKey();
        if (StringUtils.isBlank(dbSecretKey)) {
            return handleForbiddenResponse(response);
        }

        if (nonce == null || Long.parseLong(nonce) > 10000L) {
            return handleForbiddenResponse(response);
        }
        // 时间和当前时间不能超过 5 分钟
        long currentTime = System.currentTimeMillis() / 1000;
        if (timestamp == null || currentTime - Long.parseLong(timestamp) > REQUEST_DELAY_TIME) {
            return handleForbiddenResponse(response);
        }
        // 校验 secretKey  查询用户的 SecretKey
        String genSign = SignUtils.genSign(body, dbSecretKey);
        if (!genSign.equals(sign)) {
            return handleForbiddenResponse(response);
        }
        // 5.请求的模以接口是否存在？
        // 这一步不用在网关做，controller 自会校验，网关不用做
        // 6.响应日志
        log.info("响应码：" + response.getStatusCode());

        return null;
    }

    /**
     * 处理 FORBIDDEN 响应
     *
     * @param response
     * @return
     */
    private Mono<Void> handleForbiddenResponse(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        // 设置响应，结束此次请求
        return response.setComplete();
    }
}