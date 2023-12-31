Необходимо создать консольное приложение-сервис, которое принимает HTTP POST запросы: <br>

• по пути POST `/redis/incr` с json вида <br>

{
  "key": "age",
  "value": 19
}<br>

подключается к Redis DB (хост и порт указываются при запуске в параметрах `-host` и `-port`),
инкрементирует значение по ключу, указанному в "key" на значение из "value", и возвращает его в
виде:<br>

{
"value": 20
}<br>

• по пути POST `/sign/hmacsha512` с json вида <br>

{
"text": "test",
"key": "test123"
}<br>

и возвращает HMAC-SHA512 подпись значения из "text" по ключу "key" в виде hex строки <br>

• по пути POST `/postgres/users` с json вида <br>

{
"name": "Alex",
"age": 21
} <br>

создает в базе данных PostgreSQL таблицу users, если она не существует, добавляет в нее строку
("Alex", 21) и возвращает идентификатор добавленного пользователя в виде <br>

{
"id": 1
} <br>

Дополнительные условия:<br>
• можно использовать любые библиотеки для работы с http, Redis DB и PostgreSQL;<br>
• приложение должно быть протестировано unit-тестами (любой тестовый фреймворк);<br>
• результат нужно разместить на github;<br>
• наибольшее внимание следует уделить качеству коду.<br>
