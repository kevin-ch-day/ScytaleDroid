Permission Analysis Schema
==========================

This document describes the database schema used to persist permission‑first
analysis outputs (risk scores today; rationale/matrix export proposed below).

Risk snapshots
--------------

Table: `risk_scores`

Purpose: Persist a per‑run snapshot of permission risk per app for reporting
and longitudinal analysis.

Columns:

- `id` (BIGINT, PK)
- `package_name` (VARCHAR, NOT NULL)
- `app_label` (VARCHAR, NULL)
- `session_stamp` (VARCHAR, NOT NULL, e.g. `20250101-120000` UTC)
- `scope_label` (VARCHAR, NOT NULL, e.g. `All apps`, `Play & user`)
- `risk_score` (DECIMAL(7,3), NOT NULL, 0–10.000)
- `risk_grade` (CHAR(1), NOT NULL, A–F)
- `dangerous` (INT, NOT NULL)
- `signature` (INT, NOT NULL)
- `vendor` (INT, NOT NULL)
- `created_at` (TIMESTAMP, NOT NULL, default now)

DDL:

```
CREATE TABLE IF NOT EXISTS `risk_scores` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `package_name`  VARCHAR(191)    NOT NULL,
  `app_label`     VARCHAR(191)    DEFAULT NULL,
  `session_stamp` VARCHAR(32)     NOT NULL,
  `scope_label`   VARCHAR(191)    NOT NULL,
  `risk_score`    DECIMAL(7,3)    NOT NULL,
  `risk_grade`    CHAR(1)         NOT NULL,
  `dangerous`     INT             NOT NULL DEFAULT 0,
  `signature`     INT             NOT NULL DEFAULT 0,
  `vendor`        INT             NOT NULL DEFAULT 0,
  `created_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_risk_scores_session` (`session_stamp`),
  KEY `ix_risk_scores_scope` (`scope_label`),
  UNIQUE KEY `ux_risk_scores_pkg_session_scope` (`package_name`, `session_stamp`, `scope_label`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Writes are **best‑effort** from the Permission analysis CLI (no hard failure if
the DB is unavailable). See `scytaledroid/Database/db_func/risk_scores.py`.

Proposed: Rationale & Matrix export
-----------------------------------

If you want full explainability and dashboard parity, add the following:

1) Rationale per app (why a score was assigned)

```
CREATE TABLE IF NOT EXISTS `risk_rationales` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `package_name`  VARCHAR(191)    NOT NULL,
  `session_stamp` VARCHAR(32)     NOT NULL,
  `scope_label`   VARCHAR(191)    NOT NULL,
  `score_unclamped`  DECIMAL(9,6) DEFAULT NULL,
  `score_final`      DECIMAL(7,3) NOT NULL,
  `grade`            CHAR(1)      NOT NULL,
  `signals_json`     JSON         NULL,
  `combos_json`      JSON         NULL,
  `cohort_json`      JSON         NULL,
  `notes`            TEXT         NULL,
  `created_at`       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_risk_rationales_session` (`session_stamp`),
  KEY `ix_risk_rationales_scope` (`scope_label`),
  UNIQUE KEY `ux_risk_rationales_pkg_session_scope` (`package_name`, `session_stamp`, `scope_label`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

2) Matrix export (apps, permissions, cells)

```
CREATE TABLE IF NOT EXISTS `matrix_export_apps` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `abbr`          VARCHAR(8)      NOT NULL,
  `package_name`  VARCHAR(191)    NOT NULL,
  `app_label`     VARCHAR(191)    NULL,
  `session_stamp` VARCHAR(32)     NOT NULL,
  `scope_label`   VARCHAR(191)    NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_matrix_export_apps` (`abbr`,`session_stamp`,`scope_label`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `matrix_export_permissions` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `perm_name`  VARCHAR(191)    NOT NULL,
  `group_key`  VARCHAR(8)      NOT NULL,  -- LOC/CAM/MIC/…
  `row_order`  INT             NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_matrix_export_permissions` (`perm_name`,`group_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `matrix_export_cells` (
  `app_id`     BIGINT UNSIGNED NOT NULL,
  `perm_id`    BIGINT UNSIGNED NOT NULL,
  `session_stamp` VARCHAR(32)  NOT NULL,
  `scope_label`   VARCHAR(191) NOT NULL,
  `mark`          CHAR(1)      NOT NULL,  -- x/*/-
  PRIMARY KEY (`app_id`,`perm_id`,`session_stamp`,`scope_label`),
  KEY `ix_matrix_export_cells_scope` (`session_stamp`,`scope_label`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

With these, the CLI can emit the same matrix the web shows. You can either
materialize strictly the current 11 groups and curated permissions (as in CLI),
or enumerate all observed framework/vendor permissions and filter in reads.

Abbreviations
-------------

Persist app abbreviations to avoid reshuffling when labels change:

```
CREATE TABLE IF NOT EXISTS `app_abbreviations` (
  `package_name` VARCHAR(191) NOT NULL,
  `abbr`         VARCHAR(8)   NOT NULL,
  `updated_at`   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`package_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Populate this table from CLI runs (first seen) and re‑use when rendering.

Fetching data later
-------------------

- Risk trend for a package:
  ```sql
  SELECT session_stamp, risk_score, risk_grade
  FROM risk_scores
  WHERE package_name = ? AND scope_label = 'All apps'
  ORDER BY session_stamp;
  ```
- Top 10 by risk for last session:
  ```sql
  SELECT package_name, app_label, risk_score, risk_grade
  FROM risk_scores
  WHERE session_stamp = (SELECT MAX(session_stamp) FROM risk_scores)
    AND scope_label = 'All apps'
  ORDER BY risk_score DESC
  LIMIT 10;
  ```
- Matrix cells for last session/scope:
  ```sql
  SELECT a.abbr, p.perm_name, c.mark
  FROM matrix_export_cells c
  JOIN matrix_export_apps a ON a.id = c.app_id
  JOIN matrix_export_permissions p ON p.id = c.perm_id
  WHERE c.session_stamp = ? AND c.scope_label = ?
  ORDER BY a.abbr, p.row_order;
  ```

