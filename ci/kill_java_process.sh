KOTLINAPPPID=$(/root/jdk/bin/jps -l | grep backend-server-.*.jar | awk '{print $1}')
if [ -n "$KOTLINAPPPID" ]; then echo "Killing app with PID $KOTLINAPPPID" && kill -9 $KOTLINAPPPID; else echo 'App not running'; fi
