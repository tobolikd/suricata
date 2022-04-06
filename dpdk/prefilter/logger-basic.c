/* Copyright (C) 2022 Open Information Security Foundation
*
* You can copy, redistribute or modify this Program under the terms of
* the GNU General Public License version 2 as published by the Free
* Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* version 2 along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
* 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Lukas Sismis <sismis@cesnet.com>
 *
 */

#include <stdarg.h>
#include <stdio.h>

#include "logger-basic.h"

#ifndef LOGGER_BASIC_C
#define LOGGER_BASIC_C

struct logger_ops logger_basic_ops = {
    .debug = LoggerBasicDebug,
    .info = LoggerBasicInfo,
    .notice = LoggerBasicNotice,
    .warning = LoggerBasicWarning,
    .error = LoggerBasicError
};

void LoggerBasicDebug(char *format, ...) {
    if (LogLevel > PF_DEBUG)
        return;

    va_list ap;
    fprintf(stdout,"DEBUG - ");
    va_start(ap,format);
    vfprintf(stdout,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
}

void LoggerBasicInfo(char *format, ...) {
    if (LogLevel > PF_INFO)
        return;

    va_list ap;
    fprintf(stdout,"INFO - ");
    va_start(ap,format);
    vfprintf(stdout,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
}

void LoggerBasicNotice(char *format, ...) {
    if (LogLevel > PF_NOTICE)
        return;

    va_list ap;
    fprintf(stdout,"NOTICE - ");
    va_start(ap,format);
    vfprintf(stdout,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
}

void LoggerBasicWarning(int code, char *format, ...) {
    if (LogLevel > PF_WARNING)
        return;

    va_list ap;
    fprintf(stderr,"WARNING - ");
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
}

void LoggerBasicError(int code, char *format, ...) {
    if (LogLevel > PF_ERROR)
        return;

    va_list ap;
    fprintf(stderr,"ERROR - ");
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    va_end(ap);
    fprintf(stderr,"\n");
}

#endif /* LOGGER_BASIC_C */