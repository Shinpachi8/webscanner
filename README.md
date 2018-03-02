this is webscanner for test
and now it's useless and not finished.
so if you want to use it, plz wait it..



1. start arachni:   ./arachni_rest_server --reroute-to-logfile --verbose --authentication-username arachni123 --authentication-password arachni123
2. start celery:    celery -A webscanner worker -l info --time-limit 200
3. start django:    python manager.py runserver 0.0.0.0:8000
4. start flower:    flower --address=0.0.0.0:5555




1. cms 识别可以先以domain_id为单位，传进去list, 
    现在可以解析了，但是只能解析出www类型来，不知道哪里出错了。
