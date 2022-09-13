#pragma once
#include <fmt/format.h>
#include <fmt/ostream.h>
#if FMT_VERSION > 90000
// starting from v9 fmt provides formatter for std::filesystem in fmt/std.h
#include <fmt/std.h>
#endif

#include <ext/log/logger.hpp>
#include <ext/log/logging_macros.hpp>

#define LOG_FATAL(...) EXTLOG_FATAL_FMT(m_logger, __VA_ARGS__)
#define LOG_ERROR(...) EXTLOG_ERROR_FMT(m_logger, __VA_ARGS__)
#define LOG_WARN(...) EXTLOG_WARN_FMT(m_logger, __VA_ARGS__)
#define LOG_INFO(...) EXTLOG_INFO_FMT(m_logger, __VA_ARGS__)
#define LOG_DEBUG(...) EXTLOG_DEBUG_FMT(m_logger, __VA_ARGS__)
#define LOG_TRACE(...) EXTLOG_TRACE_FMT(m_logger, __VA_ARGS__)

//#define LOG_FATAL(f, ...) EXTLOG_FATAL_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_ERROR(f, ...) EXTLOG_ERROR_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_WARN(f, ...) EXTLOG_WARN_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_INFO(f, ...) EXTLOG_INFO_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_DEBUG(f, ...) EXTLOG_DEBUG_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_TRACE(f, ...) EXTLOG_TRACE_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))

#define SOCK_LOG_FATAL(f, ...) EXTLOG_FATAL_STR(m_logger, fmt::format("sock={}, " f, context->sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_ERROR(f, ...) EXTLOG_ERROR_STR(m_logger, fmt::format("sock={}, " f, context->sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_WARN(f, ...) EXTLOG_WARN_STR(m_logger, fmt::format("sock={}, " f, context->sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_INFO(f, ...) EXTLOG_INFO_STR(m_logger, fmt::format("sock={}, " f, context->sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_DEBUG(f, ...) EXTLOG_DEBUG_STR(m_logger, fmt::format("sock={}, " f, context->sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_TRACE(f, ...) EXTLOG_TRACE_STR(m_logger, fmt::format("sock={}, " f, context->sock.handle(), ##__VA_ARGS__))
