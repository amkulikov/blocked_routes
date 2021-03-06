# Blocked Routes

🚧**В РАЗРАБОТКЕ**🚧

Утилита предназначена для автоматического формирования маршрутов для серверов и клиентов OpenVPN, 
которые будут включать только заблокированные на территории РФ адреса и подсети.

Так как количество правил блокировки уже перевалило за сто тысяч, 
делать такое количество правил маршрутизации просто невозможно. Именно поэтому в утилите предусмотрен механизм 
грубого объединения адресов и подсетей в более крупные подсети. При объединении используется "жадный" алгоритм, 
стремящийся минимизровать количество НЕзаблокированных адресов в итоговых маршрутах.

## Как пользоваться

`build/blocked_routes` - актуальная сборка программы под Linux 64bit. 
Для самостоятельной сборки установите актуальную версию Golang и соберите программу при помощи `go build`.


### Формирование маршрутов
Поддерживаемые ключи запуска:
* `-src` - путь к файлу или URL с данными о заблокированных ресурсах. По умолчанию берёт данные из stdin.
* `-max` - максимальное число сформированных маршрутов.
По умолчанию сформирует отдельные маршруты для всех подсетей и отдельных адресов.
* `-silent` - отключить вывод ошибок в stderr.
* `-exclude` - исключить подсети. Два формата: либо CIDR, разделенные запятой, либо путь к файлу с исключаемыми подсетями.
* `-output` - особый формат вывода. "cidr", "ovpn", "push-ovpn".

### Использование маршрутов для управления клиентами OpenVPN

Для сообщения клиентам поддерживаемых маршрутов используется `push "route x.x.x.x y.y.y.y"` в настройках сервера.
Чтобы упростить замену маршрутов, вынесем их в отдельный файл `/etc/openvpn/routes.conf`, 
а в конфиге сервера добавим строчку `config /etc/openvpn/routes.conf`.

Например, чтобы сформировать routes.conf с максимум тысячей маршрутов, выполним:
```
./blocked_routes -src="https://github.com/zapret-info/z-i/raw/master/dump.csv" -max=1000 -output="push-ovpn" > /etc/openvpn/routes.conf
```

Чтобы применить новые настройки, перезапустите сервер openvpn.

**Маршруты на клиентах не поменяются, пока они сами не переподключатся!**

## Российские IP-адреса

Если адрес вашего VPN сервера находится под блокировкой, имеет смысл исключить из маршрутов все IP, относящиеся к РФ, 
так как к большинству из них подключиться не получится.

Список российских подсетей уже содержится в `samples/russian_nets.txt` и его можно передать с ключом `-exclude`. 
Этот список получен грубым преобразованием информации о российских IP-диапазонах При помощи `cmd/russian_nets`:

```
go run ./cmd/russian_nets/main.go ./cmd/russian_nets/geo_ip_ranges.txt > ./samples/russian_nets.txt
```