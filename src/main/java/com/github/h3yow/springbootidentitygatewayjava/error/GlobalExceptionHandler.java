package com.github.h3yow.springbootidentitygatewayjava.error;

import com.github.h3yow.springbootidentitygatewayjava.support.TimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final TimeProvider timeProvider;

    public GlobalExceptionHandler(TimeProvider timeProvider) {
        this.timeProvider = timeProvider;
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiError> handle(ApiException ex) {
        ErrorCode code = ex.errorCode();
        ApiError body = new ApiError(code.name(), ex.getMessage(), timeProvider.now());
        log.info("业务拒绝: code={}, httpStatus={}, message={}", code, code.httpStatus(), ex.getMessage());
        return ResponseEntity.status(code.httpStatus()).body(body);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex) {
        ApiError body = new ApiError(ErrorCode.INVALID_REQUEST.name(), "请求体格式不正确",
                timeProvider.now());
        return ResponseEntity.status(ErrorCode.INVALID_REQUEST.httpStatus()).body(body);
    }
}
