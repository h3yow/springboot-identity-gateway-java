package com.github.h3yow.springbootidentitygatewayjava.auth.token;

/**
 * 会话（令牌族）当前所处状态，用于区分各类拒绝结论。
 */
public enum SessionState {
    /** 活跃可用。 */
    ACTIVE,
    /** 用户按会话精准撤销。 */
    REVOKED,
    /** 因同账号会话数量达到上限，被最久未活跃会话淘汰策略挤掉。 */
    EVICTED,
    /** 刷新令牌重放检测触发的整族撤销。 */
    REPLAY_REVOKED
}
