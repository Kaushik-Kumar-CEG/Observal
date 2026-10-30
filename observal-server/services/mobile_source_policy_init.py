# SPDX-FileCopyrightText: 2026 Observal Contributors
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

"""Verify ClickHouse source retention and open the mobile read barrier after migrations."""

import asyncio

from services.clickhouse.schema import init_clickhouse

if __name__ == "__main__":
    asyncio.run(init_clickhouse())
