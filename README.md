# access-control-mechanismsWin
Программа для осуществления печати и изменения различных прав субъектов по отношению к различным объектами, а также другой информации о процессах в системе.

Консольный компоненты получает необходимую информацию о системе и сохраняет ее в файл в формате JSON. 

## Функционал
1)	Вывод информации о процессах, работающих в системе. Включает в себя следующие параметры: имя процесса, описание процесса, PID, путь до исполняемого файла, PPID и имя родительского процесса, имя владельца процесса и SID, тип процесса, среду исполнения, использование DEP и ASLR, список используемых динамических библиотек и уровень целостности. Также, для каждого из процессов можно посмотреть какими он обладает привилегиями и какие использует библиотеки;
2)	Изменение уровня целостности у любого из процессов;
3)	Изменение привилегий у любого из процессов;
4)	Вывод информации об указанном объекте системе, а именно: список контроля доступа (DACL и SACL), владелец файла и его SID, уровень целостности;
5)	Изменение списка контроля доступа включает в себя удаление записи ACE, добавление новой записи ACE и изменение прав для существующей записи ACE;
6)	Изменение владельца файла;
7)	Изменение уровня целостности файла.

## Команды
| Действие       | Команда                | Параметры | Пример  |
| ------------- |:------------------:| -----:|--:|
| Вывод информации о процессах, работающих в системе     | **procinf**    |  | procinf  |
| Изменение уровня целостности процесса     | **procchng_l**    | **PID level**<br/> PID – PID процесса, у которого нужно изменить уровень целостности;<br/> level – новый уровень целостности, нумеруется от 0 до 3, где 0 - untrusted, 1 – low, 2 - medium, 3 – high.| procchng_l 1221 1  |
| Изменение привилегий процесса     | **procchng_p**    | **PID privileges1 privileges2 …**<br/> PID – PID процесса, у которого нужно изменить привилегии;<br/> privilegiesN – номер привилегии от 0 до 35, которую нужно включить (соответствие в таблице ниже). | procchng_p 1221 0 12 13 15  |
| Вывод информации об объекте системы     | **objinf**    | **path**<br/> path – путь к файлу/папке.| objinf C:\1.docx  |
| Изменение записи ACE     | **objchng_ac**    | **path number_ace ACL_type right1 right2 …**<br/> path – путь к файлу/папке;<br/> number_ace – номер записи ACE в списке DACL/SACL;<br/> ACL_type – если изменение происходит в списке DACL, то значение равно 1, если в SACL, то 0;<br/> rightN - номер права от 0 до 15, которую нужно включить (соответствие в таблице ниже).| obgchng_ac C:\1.docx 1 0 5 6 9  |
| Удаление записи ACE     | **objchng_ad**    | **path number_ace ACL_type**<br/> path – путь к файлу/папке;<br/> number_ace – номер записи ACE в списке DACL/SACL;<br/> ACL_type – если изменение происходит в списке DACL, то значение равно 1, если в SACL, то 0.| obgchng_ad C:\1.docx 2 1  |
| Добавление записи ACE     | **objchng_aa**    | **path ACL_type owner mode right1 right2 …**<br/> path – путь к файлу/папке;<br/> ACL_type – если изменение происходит в списке DACL, то значение равно 1, если в SACL – 0;<br/> owner – субъект, которому будут предоставлены права;<br/> mode – тип записи АСЕ, для разрешения/успеха – 1, для запрета/неудачи – 0;<br/> rightN - номер права от 0 до 15, которую нужно включить (соответствие в таблице ниже).| objchng_aa C:\1.docx 1 Администраторы 1 5 6 7 9  |
| Изменение владельца     | **objchng_o**    | **path owner**<br/> path – путь к файлу/папке;<br/> owner – имя нового владельца.| objchng_o C:\1.docx Администраторы  |
| Изменение уровня целостности файла     | **objchng_l**    | **path level**<br/> path – путь к файлу/папке;<br/> owner – имя нового владельца;<br/> level – новый уровень целостности, нумеруется от 0 до 3, где 0 - untrusted, 1 – low, 2 - medium, 3 – high.| objchng_o C:\1.docx 2  |

## Соответсвие номеров и прав для объектов / привилегий для процессов
| №  | Привилегия для процессов                     | Права для объектов                |
| -- |:--------------------------------------------:| ---------------------------------:|
| 0  | SeAssignPrimaryTokenPrivilege                | Полный доступ                     |
| 1  | SeAuditPrivilege                             | Полное чтение                     |
| 2  | SeBackupPrivilege                            | Полная запись                     |
| 3  | SeChangeNotifyPrivilege                      | Полное исполнение                 |
| 4  | SeCreateGlobalPrivilege                      | Удаление                          |
| 5  | SeCreatePagefilePrivilege                    | Чтение разрешений                 |
| 6  | SeCreatePermanentPrivilege                   | Смена разрешений                  |
| 7  | SeCreateSymbolicLinkPrivilege                | Содержание папки/чтение данных    |
| 8  | SeCreateTokenPrivilege                       | Создание файлов/запись данных     |
| 9  | SeDebugPrivilege                             | Создание папок/дозапись данных    |
| 10 | SeDelegateSessionUserImpersonatePrivilege    | Траверс папок/выполнение          |
| 11 | SeEnableDelegationPrivilege                  | Изменение владельца               |
| 12 | SeImpersonatePrivilege                       | Чтение атрибутов                  |
| 13 | SeIncreaseBasePriorityPrivilege              | Запись атрибутов                  |
| 14 | SeIncreaseQuotaPrivilege                     | Чтение дополнительных атрибутов   |
| 15 | SeIncreaseWorkingSetPrivilege                | Запись дополнительных атрибутов   |
| 16 | SeLoadDriverPrivilege                        |                                   |
| 17 | SeLockMemoryPrivilege                        |                                   |
| 18 | SeMachineAccountPrivilege                    |                                   |
| 19 | SeManageVolumePrivilege                      |                                   |
| 20 | SeProfileSingleProcessPrivilege              |                                   |
| 21 | SeRelabelPrivilege                           |                                   |
| 22 | SeRemoteShutdownPrivilege                    |                                   |
| 23 | SeRestorePrivilege                           |                                   |
| 24 | SeSecurityPrivilege                          |                                   |
| 25 | SeShutdownPrivilege                          |                                   |
| 26 | SeSyncAgentPrivilege                         |                                   |
| 27 | SeSystemEnvironmentPrivilege                 |                                   |
| 28 | SeSystemProfilePrivilege                     |                                   |
| 29 | SeSystemtimePrivilege                        |                                   |
| 30 | SeTakeOwnershipPrivilege                     |                                   |
| 31 | SeTcbPrivilege                               |                                   |
| 32 | SeTimeZonePrivilege                          |                                   |
| 33 | SeTrustedCredManAccessPrivilege              |                                   |
| 34 | SeUndockPrivilege                            |                                   |
| 35 | SeUnsolicitedInputPrivilege                  |                                   |
