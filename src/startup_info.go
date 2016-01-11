package main

import (
    "fmt"
)

const (
    NTRACE_STARTUP_INFO = "\n" +
        "** =========================================================================     \n" +
        "**                                                                               \n" +
        "**                          _____                                                \n" +
        "**                      _ _|_   _| __ __ _  ___ ___                              \n" +
        "**                     | '_ \\| || '__/ _` |/ __/ _ \\                           \n" +
        "**                     | | | | || | | (_| | (_|  __/                             \n" +
        "**                     |_| |_|_||_|  \\__,_|\\___\\___|                          \n" +
        "**                                                                               \n" +
        "**                                                                               \n" +
        "**                                                                               \n" +
        "**                                                     Author: zhengyu li        \n" +
        "**                                          Email: lizhengyu419@gmail.com        \n" +
        "**                                                                               \n" +
        "** =========================================================================     \n" +
        "** \n" +
        "** \n" +
        "** Copyright (C) 2014-2016 zhengyu li <lizhengyu419@gmail.com>\n" +
        "** All rights reserved.\n" +
        "** \n" +
        "** Redistribution and use in source and binary forms, with or without\n" +
        "** modification, are permitted provided that the following conditions\n" +
        "** are met:\n" +
        "** \n" +
        "**     * Redistributions of source code must retain the above copyright\n" +
        "**       notice, this list of conditions and the following disclaimer.\n" +
        "**     * Redistributions in binary form must reproduce the above copyright\n" +
        "**       notice, this list of conditions and the following disclaimer in\n" +
        "**       the documentation and/or other materials provided with the\n" +
        "**       distribution.\n" +
        "**     * Neither the name of Redis nor the names of its contributors may\n" +
        "**       be used to endorse or promote products derived from this software\n" +
        "**       without specific prior written permission.\n" +
        "** \n" +
        "** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n" +
        "** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n" +
        "** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n" +
        "** ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE\n" +
        "** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\n" +
        "** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR\n" +
        "** SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER\n" +
        "** CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,\n" +
        "** OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n" +
        "** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n" +
        "\n"
)

func displayNtraceStartupInfo() {
    fmt.Printf("%s", NTRACE_STARTUP_INFO)
}
