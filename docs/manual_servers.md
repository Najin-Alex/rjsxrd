# Ручное добавление серверов

## Описание

В проекте реализована возможность ручного добавления VPN-серверов через файл `source/config/servers.txt`. Это позволяет пользователям добавлять собственные серверы, которые будут автоматически обрабатываться, фильтроваться и объединяться с остальными конфигурациями.

## Использование

1. Добавьте свои серверы в файл `source/config/servers.txt`, по одному на строку
2. Серверы должны быть в формате поддерживаемых протоколов: `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`, `tuic://`, `hysteria://`, `hysteria2://`, `hy2://`
3. При следующем запуске генератора, ваши серверы будут:
   - Объединены с остальными источниками
   - Протестированы на безопасность (фильтрация insecure параметров)
   - Обработаны через SNI/CIDR фильтрацию для bypass-конфигураций
   - Включены в итоговые файлы (default, bypass, split-by-protocols и т.д.)

## Пример содержимого servers.txt

```
vless://6963526294e8b733e25ca030@104.248.129.52:52496?type=tcp&security=reality&pbk=Tmdubjerl-x6RC2yaINZ6zln3Pjnbzr9oVZ8izzn3Es&fp=random&sni=yahoo.com&sid=a889244085d63e66&spx=%2F#SAU-VPN
vmess://eyJhZGQiOiIxODUuMTQxLjIxNi4yMjkiLCJhaWQiOiIwIiwiYWxwbiI6IiIsImZwIjoiIiwiaG9zdCI6IiIsImlkIjoiYjgyZDVhMWQtODhiZS00N2VhLWI1OWQtMmViMGEzNmIzOTIyIiwibmV0IjoidGNwIiwicGF0aCI6IiIsInBvcnQiOiI4NDQzIiwicHMiOiJDYW5hZGEiLCJzY3kiOiJhdXRvIiwic2tpcC1jZXJ0LXZlcmlmeSI6ZmFsc2UsInNuaSI6Imlnbi5kZXYiLCJ0bHMiOiJyZWFsaXR5IiwidHlwZSI6IiIsInYiOiIyIn0=
trojan://password@example.com:443?security=tls&sni=example.com#Trojan-Server
```

## Функциональность

- Все серверы из `servers.txt` автоматически проходят ту же обработку, что и серверы из URL-источников
- Применяются все фильтры безопасности и дедупликация
- Серверы включаются в все типы выходных файлов (номерные, all.txt, all-secure.txt, bypass и т.д.)
- Поддерживаются все форматы VPN-конфигураций, поддерживаемые системой