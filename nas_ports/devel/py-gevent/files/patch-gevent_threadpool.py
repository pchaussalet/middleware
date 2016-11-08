--- gevent/threadpool.py
+++ gevent/threadpool.py
@@ -283,8 +283,6 @@ class ThreadResult(object):
             # LoopExit (XXX: Why?)
             self._call_when_ready()
         try:
-            if self.exc_info:
-                self.hub.handle_error(self.context, *self.exc_info)
             self.context = None
             self.async = None
             self.hub = None