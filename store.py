"""Durable Redis state via Upstash REST (never store state only in memory)."""
import json
import os
import requests


class StorageError(Exception):
    pass


class RedisStore:
    def __init__(self):
        self.url = os.getenv('UPSTASH_REDIS_REST_URL', '').rstrip('/')
        self.token = os.getenv('UPSTASH_REDIS_REST_TOKEN', '')

    def command(self, *parts):
        if not self.url or not self.token:
            raise StorageError('Upstash credentials missing')
        try:
            r = requests.post(
                self.url,
                headers={'Authorization': 'Bearer ' + self.token,
                         'Content-Type': 'application/json'},
                json=list(parts), timeout=(3, 7),
            )
            r.raise_for_status()
            data = r.json()
            if 'error' in data:
                raise StorageError('Redis command failed')
            return data['result']
        except (requests.RequestException, ValueError, KeyError) as exc:
            raise StorageError('Persistent storage unavailable') from exc

    def get(self, key):
        v = self.command('GET', key)
        return None if v is None else json.loads(v)

    def mget(self, keys):
        if not keys:
            return []
        vals = self.command('MGET', *keys)
        return [None if v is None else json.loads(v) for v in vals]

    def set(self, key, value, nx=False, ttl=None):
        args = ['SET', key, json.dumps(value, ensure_ascii=False, separators=(',', ':'))]
        if nx:
            args.append('NX')
        if ttl is not None:
            args.extend(['EX', ttl])
        return self.command(*args) == 'OK'

    def cas(self, key, old, new):
        # Compare and swap is atomic: two concurrent commits cannot both win.
        script = '''
        if redis.call('GET', KEYS[1]) == ARGV[1] then
          redis.call('SET', KEYS[1], ARGV[2])
          return 1
        end
        return 0
        '''
        return self.command('EVAL', script, 1, key,
            json.dumps(old, ensure_ascii=False, separators=(',', ':')),
            json.dumps(new, ensure_ascii=False, separators=(',', ':'))) == 1

    def release(self, key, reservation):
        # Never delete someone else's reservation.
        script = '''
        if redis.call('GET', KEYS[1]) == ARGV[1] then
          return redis.call('DEL', KEYS[1])
        end
        return 0
        '''
        self.command('EVAL', script, 1, key,
            json.dumps(reservation, ensure_ascii=False, separators=(',', ':')))

    def set_many_nx(self, entries):
        if not entries:
            return
        if not self.url or not self.token:
            raise StorageError('Upstash credentials missing')
        commands = [
            ['SET', key, json.dumps(value, ensure_ascii=False, separators=(',', ':')), 'NX']
            for key, value in entries
        ]
        try:
            r = requests.post(self.url + '/pipeline',
                 headers={'Authorization': 'Bearer ' + self.token,
                          'Content-Type': 'application/json'},
                 json=commands, timeout=(3, 9))
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, list) or len(data) != len(entries) or any(
                    not isinstance(x, dict) or 'error' in x for x in data):
                raise StorageError('Redis bulk save failed')
        except (requests.RequestException, ValueError) as exc:
            raise StorageError('Persistent storage unavailable') from exc
