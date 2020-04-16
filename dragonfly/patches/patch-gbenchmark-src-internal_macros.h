--- src/internal_macros.h.orig	2020-04-15 14:43:24 UTC
+++ src/internal_macros.h
@@ -54,6 +54,9 @@
   #endif
 #elif defined(__FreeBSD__)
   #define BENCHMARK_OS_FREEBSD 1
+#elif defined(__DragonFly__)
+  #define BENCHMARK_OS_FREEBSD 1
+  #define BENCHMARK_OS_DRAGONFLY 1
 #elif defined(__NetBSD__)
   #define BENCHMARK_OS_NETBSD 1
 #elif defined(__OpenBSD__)
