# 盲标卷（72 小时重标）

- 冻结时间：2026-11-03T11:29:50+00:00    出卷时间：2026-11-07T16:05:13+00:00
- 冻结 sha256：`a60a3c01aafc61d2eb2231c9b218bbf82e35c1c6ef0a520a867052e31f0b5140`
- 条目数：107

**规则**：不许翻 `bench/labels/`、不许翻 `docs/pilot_findings.md`，
只按 `docs/labeling_spec.md` 的规范、对着跑起来的靶场重新判一遍。
判不准就填 `uncertain`，那本身是结论。

| # | id | 方法 | 路径 | 对象标识 | 属主 | vulnerable | difficulty | 备注 |
|---|---|---|---|---|---|---|---|---|
| 1 | crapi-0036 | GET | `/workshop/api/mechanic/download_report` | `report_7` | bob |  |  |  |
| 2 | crapi-0006 | GET | `/workshop/api/shop/orders/{id}` | `11` | carol |  |  |  |
| 3 | crapi-0039 | DELETE | `/workshop/api/mechanic/download_report` | `report_8` | carol |  |  |  |
| 4 | mock-0001 | GET | `/api/orders/{id}` | `1001` | alice |  |  |  |
| 5 | mock-0005 | GET | `/api/orders/{id}` | `1005` | carol |  |  |  |
| 6 | crapi-0025 | GET | `/workshop/api/mechanic/service_request/{id}` | `8` | carol |  |  |  |
| 7 | mock-0039 | DELETE | `/api/documents/{uuid}` | `a1b2c3d4-0001-4000-8000-000000000001` | alice |  |  |  |
| 8 | crapi-0026 | GET | `/workshop/api/mechanic/service_request/{id}/comment` | `8` | carol |  |  |  |
| 9 | vampi-0006 | PUT | `/users/v1/{username}/password` | `bob2` | bob2 |  |  |  |
| 10 | crapi-0024 | GET | `/community/api/v2/community/posts/{postId}` | `DvDozYzPrTSN8ZFh6mC82W` | bob |  |  |  |
| 11 | crapi-0044 | GET | `/workshop/api/mechanic/mechanic_report` | `8` | carol |  |  |  |
| 12 | mock-0024 | PATCH | `/api/orders/{id}` | `1003` | bob |  |  |  |
| 13 | crapi-0023 | GET | `/workshop/api/mechanic/service_request/{id}/comment` | `7` | bob |  |  |  |
| 14 | vampi-0005 | GET | `/books/v1/{bookTitle}` | `bob2-notebook` | bob2 |  |  |  |
| 15 | mock-0020 | GET | `/api/orders/{id}/items` | `1004` | bob |  |  |  |
| 16 | mock-0048 | GET | `/api/documents/{uuid}` | `a1b2c3d4-0001-4000-8000-000000000001` | alice |  |  |  |
| 17 | mock-0029 | POST | `/api/orders/batch` | `1005` | carol |  |  |  |
| 18 | mock-0008 | GET | `/api/users/{id}/orders` | `3` | carol |  |  |  |
| 19 | mock-0043 | DELETE | `/api/documents/{uuid}` | `c1b2c3d4-0005-4000-8000-000000000005` | carol |  |  |  |
| 20 | vampi-0012 | GET | `/users/v1/{username}` | `carol3` | carol3 |  |  |  |
| 21 | crapi-0003 | GET | `/workshop/api/shop/orders/{id}` | `8` | bob |  |  |  |
| 22 | mock-0050 | GET | `/api/documents/{uuid}` | `c1b2c3d4-0005-4000-8000-000000000005` | carol |  |  |  |
| 23 | crapi-0005 | GET | `/workshop/api/shop/orders/{id}` | `10` | carol |  |  |  |
| 24 | crapi-0035 | DELETE | `/workshop/api/mechanic/download_report` | `report_6` | alice |  |  |  |
| 25 | mock-0035 | GET | `/api/orders/export` | `1005` | carol |  |  |  |
| 26 | mock-0049 | GET | `/api/documents/{uuid}` | `b1b2c3d4-0003-4000-8000-000000000003` | bob |  |  |  |
| 27 | crapi-0028 | POST | `/community/api/v2/community/posts/{postId}/comment` | `A3PrAj72bxvcDWCDoZ5cGG` | alice |  |  |  |
| 28 | mock-0046 | GET | `/api/documents/{uuid}/trash` | `c1b2c3d4-0005-4000-8000-000000000005` | carol |  |  |  |
| 29 | mock-0045 | GET | `/api/documents/{uuid}/trash` | `b1b2c3d4-0003-4000-8000-000000000003` | bob |  |  |  |
| 30 | vampi-0009 | GET | `/books/v1/{bookTitle}` | `carol3-notebook` | carol3 |  |  |  |
| 31 | crapi-0013 | GET | `/identity/api/v2/vehicle/{uuid}/location` | `56b739aa-7f85-4dbb-8d79-0c31051d6677` | alice |  |  |  |
| 32 | crapi-0022 | GET | `/workshop/api/mechanic/service_request/{id}` | `7` | bob |  |  |  |
| 33 | crapi-0034 | GET | `/workshop/api/mechanic/download_report` | `report_6` | alice |  |  |  |
| 34 | mock-0036 | GET | `/api/orders/export/mine` | `1001,1002` | alice |  |  |  |
| 35 | mock-0034 | GET | `/api/orders/export` | `1003,1004` | bob |  |  |  |
| 36 | vampi-0007 | PUT | `/users/v1/{username}/email` | `bob2` | bob2 |  |  |  |
| 37 | mock-0026 | PATCH | `/api/orders/{id}` | `1005` | carol |  |  |  |
| 38 | crapi-0002 | GET | `/workshop/api/shop/orders/{id}` | `7` | alice |  |  |  |
| 39 | vampi-0002 | PUT | `/users/v1/{username}/password` | `alice1` | alice1 |  |  |  |
| 40 | crapi-0011 | DELETE | `/workshop/api/shop/orders/{id}` | `10` | carol |  |  |  |
| 41 | crapi-0010 | DELETE | `/workshop/api/shop/orders/{id}` | `9` | bob |  |  |  |
| 42 | mock-0011 | DELETE | `/api/orders/{id}` | `1003` | bob |  |  |  |
| 43 | crapi-0019 | GET | `/workshop/api/mechanic/service_request/{id}` | `6` | alice |  |  |  |
| 44 | crapi-0007 | DELETE | `/workshop/api/shop/orders/{id}` | `6` | alice |  |  |  |
| 45 | crapi-0032 | PUT | `/workshop/api/mechanic/service_request/{id}` | `7` | bob |  |  |  |
| 46 | mock-0002 | GET | `/api/orders/{id}` | `1002` | alice |  |  |  |
| 47 | mock-0031 | POST | `/api/orders/batch/mine` | `1003,1004` | bob |  |  |  |
| 48 | crapi-0020 | GET | `/workshop/api/mechanic/service_request/{id}/comment` | `6` | alice |  |  |  |
| 49 | crapi-0021 | GET | `/community/api/v2/community/posts/{postId}` | `A3PrAj72bxvcDWCDoZ5cGG` | alice |  |  |  |
| 50 | mock-0014 | GET | `/api/profile/{id}` | `1` | alice |  |  |  |
| 51 | mock-0022 | PATCH | `/api/orders/{id}` | `1001` | alice |  |  |  |
| 52 | vampi-0004 | GET | `/users/v1/{username}` | `alice1` | alice1 |  |  |  |
| 53 | mock-0037 | GET | `/api/orders/export/mine` | `1003,1004` | bob |  |  |  |
| 54 | mock-0003 | GET | `/api/orders/{id}` | `1003` | bob |  |  |  |
| 55 | mock-0017 | GET | `/api/orders/{id}/items` | `1001` | alice |  |  |  |
| 56 | vampi-0011 | PUT | `/users/v1/{username}/email` | `carol3` | carol3 |  |  |  |
| 57 | mock-0038 | GET | `/api/orders/export/mine` | `1005` | carol |  |  |  |
| 58 | mock-0013 | DELETE | `/api/orders/{id}` | `1005` | carol |  |  |  |
| 59 | crapi-0042 | GET | `/workshop/api/mechanic/mechanic_report` | `7` | bob |  |  |  |
| 60 | crapi-0004 | GET | `/workshop/api/shop/orders/{id}` | `9` | bob |  |  |  |
| 61 | mock-0009 | DELETE | `/api/orders/{id}` | `1001` | alice |  |  |  |
| 62 | crapi-0027 | GET | `/community/api/v2/community/posts/{postId}` | `CBSVK3D3WFegKi464RoqnG` | carol |  |  |  |
| 63 | crapi-0014 | GET | `/identity/api/v2/vehicle/{uuid}/location` | `c52858a6-3743-4d7f-9e76-669215d30fe9` | bob |  |  |  |
| 64 | mock-0006 | GET | `/api/users/{id}/orders` | `1` | alice |  |  |  |
| 65 | mock-0047 | GET | `/api/documents/{uuid}/trash` | `a1b2c3d4-0002-4000-8000-000000000002` | alice |  |  |  |
| 66 | crapi-0001 | GET | `/workshop/api/shop/orders/{id}` | `6` | alice |  |  |  |
| 67 | crapi-0041 | DELETE | `/workshop/api/mechanic/mechanic_report` | `6` | alice |  |  |  |
| 68 | mock-0030 | POST | `/api/orders/batch/mine` | `1001,1002` | alice |  |  |  |
| 69 | crapi-0012 | DELETE | `/workshop/api/shop/orders/{id}` | `11` | carol |  |  |  |
| 70 | crapi-0017 | GET | `/workshop/api/merchant/service_requests/{vin}` | `3XXT60864E93Z0BS4` | bob |  |  |  |
| 71 | mock-0028 | POST | `/api/orders/batch` | `1003,1004` | bob |  |  |  |
| 72 | mock-0040 | DELETE | `/api/documents/{uuid}` | `a1b2c3d4-0002-4000-8000-000000000002` | alice |  |  |  |
| 73 | mock-0010 | DELETE | `/api/orders/{id}` | `1002` | alice |  |  |  |
| 74 | mock-0004 | GET | `/api/orders/{id}` | `1004` | bob |  |  |  |
| 75 | mock-0016 | GET | `/api/profile/{id}` | `3` | carol |  |  |  |
| 76 | vampi-0001 | GET | `/books/v1/{bookTitle}` | `alice1-notebook` | alice1 |  |  |  |
| 77 | mock-0032 | POST | `/api/orders/batch/mine` | `1005` | carol |  |  |  |
| 78 | mock-0027 | POST | `/api/orders/batch` | `1001,1002` | alice |  |  |  |
| 79 | crapi-0031 | PUT | `/workshop/api/mechanic/service_request/{id}` | `6` | alice |  |  |  |
| 80 | mock-0044 | GET | `/api/documents/{uuid}/trash` | `a1b2c3d4-0001-4000-8000-000000000001` | alice |  |  |  |
| 81 | crapi-0009 | DELETE | `/workshop/api/shop/orders/{id}` | `8` | bob |  |  |  |
| 82 | crapi-0037 | DELETE | `/workshop/api/mechanic/download_report` | `report_7` | bob |  |  |  |
| 83 | mock-0041 | DELETE | `/api/documents/{uuid}` | `b1b2c3d4-0003-4000-8000-000000000003` | bob |  |  |  |
| 84 | crapi-0043 | DELETE | `/workshop/api/mechanic/mechanic_report` | `7` | bob |  |  |  |
| 85 | crapi-0015 | GET | `/identity/api/v2/vehicle/{uuid}/location` | `4818581c-a2c6-4115-ba43-16a61073330a` | carol |  |  |  |
| 86 | crapi-0033 | PUT | `/workshop/api/mechanic/service_request/{id}` | `8` | carol |  |  |  |
| 87 | mock-0042 | DELETE | `/api/documents/{uuid}` | `b1b2c3d4-0004-4000-8000-000000000004` | bob |  |  |  |
| 88 | vampi-0008 | GET | `/users/v1/{username}` | `bob2` | bob2 |  |  |  |
| 89 | crapi-0008 | DELETE | `/workshop/api/shop/orders/{id}` | `7` | alice |  |  |  |
| 90 | mock-0023 | PATCH | `/api/orders/{id}` | `1002` | alice |  |  |  |
| 91 | mock-0015 | GET | `/api/profile/{id}` | `2` | bob |  |  |  |
| 92 | crapi-0016 | GET | `/workshop/api/merchant/service_requests/{vin}` | `9N6L4W48LEC91XD38` | alice |  |  |  |
| 93 | crapi-0040 | GET | `/workshop/api/mechanic/mechanic_report` | `6` | alice |  |  |  |
| 94 | crapi-0038 | GET | `/workshop/api/mechanic/download_report` | `report_8` | carol |  |  |  |
| 95 | crapi-0045 | DELETE | `/workshop/api/mechanic/mechanic_report` | `8` | carol |  |  |  |
| 96 | vampi-0003 | PUT | `/users/v1/{username}/email` | `alice1` | alice1 |  |  |  |
| 97 | mock-0033 | GET | `/api/orders/export` | `1001,1002` | alice |  |  |  |
| 98 | crapi-0018 | GET | `/workshop/api/merchant/service_requests/{vin}` | `11ZU9TJW463655KZ1` | carol |  |  |  |
| 99 | mock-0007 | GET | `/api/users/{id}/orders` | `2` | bob |  |  |  |
| 100 | mock-0018 | GET | `/api/orders/{id}/items` | `1002` | alice |  |  |  |
| 101 | crapi-0029 | POST | `/community/api/v2/community/posts/{postId}/comment` | `DvDozYzPrTSN8ZFh6mC82W` | bob |  |  |  |
| 102 | crapi-0030 | POST | `/community/api/v2/community/posts/{postId}/comment` | `CBSVK3D3WFegKi464RoqnG` | carol |  |  |  |
| 103 | mock-0025 | PATCH | `/api/orders/{id}` | `1004` | bob |  |  |  |
| 104 | vampi-0010 | PUT | `/users/v1/{username}/password` | `carol3` | carol3 |  |  |  |
| 105 | mock-0021 | GET | `/api/orders/{id}/items` | `1005` | carol |  |  |  |
| 106 | mock-0019 | GET | `/api/orders/{id}/items` | `1003` | bob |  |  |  |
| 107 | mock-0012 | DELETE | `/api/orders/{id}` | `1004` | bob |  |  |  |
