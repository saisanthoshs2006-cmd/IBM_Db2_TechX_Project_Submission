-- =============================================================================
-- 002_demo_data.sql  -  Synthetic enterprise sales dataset (schema DB2INTEL_DEMO)
-- Target : IBM Db2 11.5+ (no 12.x-only features used here)
-- Scope  : creates objects ONLY in schema DB2INTEL_DEMO. Never references DB2INST1.
-- Apply  : python -m db2intel.db.migrate up   (runs after 001_schema_meta.sql)
-- Data   : fully deterministic (MOD arithmetic, no RAND), so every run yields
--          identical rows. Company names are invented brand words plus a generic
--          industry word. Products are generic descriptions. Cities and countries
--          are real places but carry no personal data. No people are stored.
-- Volume : 6 regions, 24 products, 240 customers, 3000 orders, 7500 order lines.
-- =============================================================================

CREATE SCHEMA DB2INTEL_DEMO;

-- -----------------------------------------------------------------------------
-- Tables
-- -----------------------------------------------------------------------------
CREATE TABLE DB2INTEL_DEMO.REGION (
    REGION_ID    SMALLINT     NOT NULL,
    REGION_CODE  CHAR(3)      NOT NULL,
    REGION_NAME  VARCHAR(64)  NOT NULL,
    GEO          VARCHAR(8)   NOT NULL,
    CONSTRAINT PK_REGION PRIMARY KEY (REGION_ID),
    CONSTRAINT UQ_REGION_CODE UNIQUE (REGION_CODE),
    CONSTRAINT UQ_REGION_NAME UNIQUE (REGION_NAME),
    CONSTRAINT CK_REGION_GEO CHECK (GEO IN ('AMERICAS', 'EMEA', 'APAC'))
);

CREATE TABLE DB2INTEL_DEMO.CUSTOMER (
    CUSTOMER_ID     INTEGER        NOT NULL,
    CUSTOMER_CODE   VARCHAR(10)    NOT NULL,
    COMPANY_NAME    VARCHAR(100)   NOT NULL,
    INDUSTRY        VARCHAR(32)    NOT NULL,
    SEGMENT         VARCHAR(12)    NOT NULL,
    REGION_ID       SMALLINT       NOT NULL,
    COUNTRY         VARCHAR(48)    NOT NULL,
    CITY            VARCHAR(48)    NOT NULL,
    CREDIT_LIMIT    DECIMAL(12, 2) NOT NULL,
    CUSTOMER_SINCE  DATE           NOT NULL,
    IS_ACTIVE       SMALLINT       NOT NULL DEFAULT 1,
    CONSTRAINT PK_CUSTOMER PRIMARY KEY (CUSTOMER_ID),
    CONSTRAINT UQ_CUSTOMER_CODE UNIQUE (CUSTOMER_CODE),
    CONSTRAINT UQ_CUSTOMER_NAME UNIQUE (COMPANY_NAME),
    CONSTRAINT FK_CUSTOMER_REGION FOREIGN KEY (REGION_ID)
        REFERENCES DB2INTEL_DEMO.REGION (REGION_ID) ON DELETE RESTRICT,
    CONSTRAINT CK_CUSTOMER_SEGMENT CHECK (SEGMENT IN ('ENTERPRISE', 'MID_MARKET', 'SMB')),
    CONSTRAINT CK_CUSTOMER_CREDIT CHECK (CREDIT_LIMIT >= 0),
    CONSTRAINT CK_CUSTOMER_ACTIVE CHECK (IS_ACTIVE IN (0, 1))
);

CREATE INDEX DB2INTEL_DEMO.IX_CUSTOMER_REGION  ON DB2INTEL_DEMO.CUSTOMER (REGION_ID);
CREATE INDEX DB2INTEL_DEMO.IX_CUSTOMER_SEGMENT ON DB2INTEL_DEMO.CUSTOMER (SEGMENT, INDUSTRY);

CREATE TABLE DB2INTEL_DEMO.PRODUCT (
    PRODUCT_ID    INTEGER        NOT NULL,
    SKU           VARCHAR(16)    NOT NULL,
    PRODUCT_NAME  VARCHAR(100)   NOT NULL,
    CATEGORY      VARCHAR(32)    NOT NULL,
    UNIT_PRICE    DECIMAL(10, 2) NOT NULL,
    UNIT_COST     DECIMAL(10, 2) NOT NULL,
    LAUNCH_DATE   DATE           NOT NULL,
    IS_ACTIVE     SMALLINT       NOT NULL DEFAULT 1,
    CONSTRAINT PK_PRODUCT PRIMARY KEY (PRODUCT_ID),
    CONSTRAINT UQ_PRODUCT_SKU UNIQUE (SKU),
    CONSTRAINT CK_PRODUCT_CATEGORY CHECK (CATEGORY IN
        ('Software', 'Cloud Services', 'Hardware', 'Support', 'Professional Services', 'Data and AI')),
    CONSTRAINT CK_PRODUCT_PRICE CHECK (UNIT_PRICE > 0),
    CONSTRAINT CK_PRODUCT_COST CHECK (UNIT_COST >= 0 AND UNIT_COST <= UNIT_PRICE),
    CONSTRAINT CK_PRODUCT_ACTIVE CHECK (IS_ACTIVE IN (0, 1))
);

CREATE INDEX DB2INTEL_DEMO.IX_PRODUCT_CATEGORY ON DB2INTEL_DEMO.PRODUCT (CATEGORY);

CREATE TABLE DB2INTEL_DEMO.SALES_ORDER (
    ORDER_ID      INTEGER      NOT NULL,
    ORDER_NUMBER  VARCHAR(12)  NOT NULL,
    CUSTOMER_ID   INTEGER      NOT NULL,
    ORDER_DATE    DATE         NOT NULL,
    SHIP_DATE     DATE,
    STATUS        VARCHAR(10)  NOT NULL,
    CHANNEL       VARCHAR(8)   NOT NULL,
    CONSTRAINT PK_SALES_ORDER PRIMARY KEY (ORDER_ID),
    CONSTRAINT UQ_SALES_ORDER_NUMBER UNIQUE (ORDER_NUMBER),
    CONSTRAINT FK_SALES_ORDER_CUSTOMER FOREIGN KEY (CUSTOMER_ID)
        REFERENCES DB2INTEL_DEMO.CUSTOMER (CUSTOMER_ID) ON DELETE RESTRICT,
    CONSTRAINT CK_SALES_ORDER_STATUS CHECK (STATUS IN ('PENDING', 'SHIPPED', 'DELIVERED', 'CANCELLED', 'RETURNED')),
    CONSTRAINT CK_SALES_ORDER_CHANNEL CHECK (CHANNEL IN ('ONLINE', 'DIRECT', 'PARTNER')),
    CONSTRAINT CK_SALES_ORDER_SHIP_AFTER CHECK (SHIP_DATE IS NULL OR SHIP_DATE >= ORDER_DATE),
    CONSTRAINT CK_SALES_ORDER_SHIP_STATUS CHECK (
        (STATUS IN ('PENDING', 'CANCELLED') AND SHIP_DATE IS NULL)
        OR (STATUS IN ('SHIPPED', 'DELIVERED', 'RETURNED') AND SHIP_DATE IS NOT NULL))
);

CREATE INDEX DB2INTEL_DEMO.IX_SALES_ORDER_CUSTOMER ON DB2INTEL_DEMO.SALES_ORDER (CUSTOMER_ID, ORDER_DATE);
CREATE INDEX DB2INTEL_DEMO.IX_SALES_ORDER_DATE     ON DB2INTEL_DEMO.SALES_ORDER (ORDER_DATE, STATUS);

CREATE TABLE DB2INTEL_DEMO.ORDER_ITEM (
    ORDER_ID      INTEGER        NOT NULL,
    LINE_NO       SMALLINT       NOT NULL,
    PRODUCT_ID    INTEGER        NOT NULL,
    QUANTITY      INTEGER        NOT NULL,
    UNIT_PRICE    DECIMAL(10, 2) NOT NULL,
    DISCOUNT_PCT  DECIMAL(5, 2)  NOT NULL DEFAULT 0,
    LINE_AMOUNT   DECIMAL(14, 2) GENERATED ALWAYS AS
                  (DECIMAL(QUANTITY * UNIT_PRICE * (100 - DISCOUNT_PCT) / 100, 14, 2)),
    CONSTRAINT PK_ORDER_ITEM PRIMARY KEY (ORDER_ID, LINE_NO),
    CONSTRAINT FK_ORDER_ITEM_ORDER FOREIGN KEY (ORDER_ID)
        REFERENCES DB2INTEL_DEMO.SALES_ORDER (ORDER_ID) ON DELETE CASCADE,
    CONSTRAINT FK_ORDER_ITEM_PRODUCT FOREIGN KEY (PRODUCT_ID)
        REFERENCES DB2INTEL_DEMO.PRODUCT (PRODUCT_ID) ON DELETE RESTRICT,
    CONSTRAINT CK_ORDER_ITEM_LINE CHECK (LINE_NO > 0),
    CONSTRAINT CK_ORDER_ITEM_QTY CHECK (QUANTITY > 0),
    CONSTRAINT CK_ORDER_ITEM_PRICE CHECK (UNIT_PRICE >= 0),
    CONSTRAINT CK_ORDER_ITEM_DISCOUNT CHECK (DISCOUNT_PCT BETWEEN 0 AND 100)
);

CREATE INDEX DB2INTEL_DEMO.IX_ORDER_ITEM_PRODUCT ON DB2INTEL_DEMO.ORDER_ITEM (PRODUCT_ID);

-- -----------------------------------------------------------------------------
-- Convenience view: one row per order with revenue, cost and customer context.
-- -----------------------------------------------------------------------------
CREATE VIEW DB2INTEL_DEMO.V_ORDER_SUMMARY AS
SELECT O.ORDER_ID, O.ORDER_NUMBER, O.ORDER_DATE, O.SHIP_DATE, O.STATUS, O.CHANNEL,
       C.CUSTOMER_ID, C.COMPANY_NAME, C.SEGMENT, C.INDUSTRY,
       R.REGION_ID, R.REGION_NAME, R.GEO,
       COUNT(*)                                   AS LINE_COUNT,
       SUM(I.QUANTITY)                            AS TOTAL_UNITS,
       SUM(DECIMAL(I.QUANTITY * I.UNIT_PRICE, 14, 2)) AS GROSS_AMOUNT,
       SUM(I.LINE_AMOUNT)                         AS NET_AMOUNT,
       SUM(DECIMAL(I.QUANTITY * P.UNIT_COST, 14, 2))  AS COST_AMOUNT
FROM DB2INTEL_DEMO.SALES_ORDER O
JOIN DB2INTEL_DEMO.CUSTOMER   C ON C.CUSTOMER_ID = O.CUSTOMER_ID
JOIN DB2INTEL_DEMO.REGION     R ON R.REGION_ID   = C.REGION_ID
JOIN DB2INTEL_DEMO.ORDER_ITEM I ON I.ORDER_ID    = O.ORDER_ID
JOIN DB2INTEL_DEMO.PRODUCT    P ON P.PRODUCT_ID  = I.PRODUCT_ID
GROUP BY O.ORDER_ID, O.ORDER_NUMBER, O.ORDER_DATE, O.SHIP_DATE, O.STATUS, O.CHANNEL,
         C.CUSTOMER_ID, C.COMPANY_NAME, C.SEGMENT, C.INDUSTRY,
         R.REGION_ID, R.REGION_NAME, R.GEO;

-- -----------------------------------------------------------------------------
-- Catalog documentation. These REMARKS are what the copilot embeds into
-- DB2INTEL.SCHEMA_EMBEDDING, so they are written for semantic search.
-- -----------------------------------------------------------------------------
COMMENT ON TABLE DB2INTEL_DEMO.REGION          IS 'Sales regions (territories) grouped into geographies AMERICAS, EMEA and APAC';
COMMENT ON TABLE DB2INTEL_DEMO.CUSTOMER        IS 'Business customers (accounts, clients, companies) with industry, segment, location and credit limit';
COMMENT ON TABLE DB2INTEL_DEMO.PRODUCT         IS 'Product and service catalog with list price, unit cost and category';
COMMENT ON TABLE DB2INTEL_DEMO.SALES_ORDER     IS 'Sales orders (purchases, deals, bookings) placed by customers, with order date, status and sales channel';
COMMENT ON TABLE DB2INTEL_DEMO.ORDER_ITEM      IS 'Order lines: product, quantity, price, discount and net line amount (revenue) for each sales order';
COMMENT ON TABLE DB2INTEL_DEMO.V_ORDER_SUMMARY IS 'One row per order with customer, region, gross revenue, net revenue, cost and units. Use for revenue and margin analysis';

COMMENT ON DB2INTEL_DEMO.REGION (
    REGION_CODE IS 'Three-letter region code, for example NAM, EUR, IND',
    GEO         IS 'Geography that groups regions: AMERICAS, EMEA or APAC');

COMMENT ON DB2INTEL_DEMO.CUSTOMER (
    CUSTOMER_CODE  IS 'Business key of the customer, format CUS-00001',
    COMPANY_NAME   IS 'Name of the customer company (fictional)',
    INDUSTRY       IS 'Industry vertical such as Banking, Healthcare, Retail, Manufacturing',
    SEGMENT        IS 'Customer size segment: ENTERPRISE, MID_MARKET or SMB',
    CREDIT_LIMIT   IS 'Approved credit limit in USD',
    CUSTOMER_SINCE IS 'Date the customer account was opened',
    IS_ACTIVE      IS '1 if the customer account is active, 0 if churned or closed');

COMMENT ON DB2INTEL_DEMO.PRODUCT (
    SKU          IS 'Stock keeping unit, the product business key',
    CATEGORY     IS 'Product line: Software, Cloud Services, Hardware, Support, Professional Services, Data and AI',
    UNIT_PRICE   IS 'Current list price per unit in USD',
    UNIT_COST    IS 'Cost to deliver one unit in USD, used for margin',
    LAUNCH_DATE  IS 'Date the product became available',
    IS_ACTIVE    IS '1 if the product is currently sold, 0 if discontinued');

COMMENT ON DB2INTEL_DEMO.SALES_ORDER (
    ORDER_NUMBER IS 'Business key of the order, format SO-000001',
    ORDER_DATE   IS 'Date the order was placed (booking date)',
    SHIP_DATE    IS 'Date the order shipped, NULL while pending or if cancelled',
    STATUS       IS 'Order lifecycle status: PENDING, SHIPPED, DELIVERED, CANCELLED, RETURNED',
    CHANNEL      IS 'Sales channel: ONLINE, DIRECT sales team or PARTNER reseller');

COMMENT ON DB2INTEL_DEMO.ORDER_ITEM (
    QUANTITY     IS 'Units ordered on this line',
    UNIT_PRICE   IS 'Price per unit in USD at the time of the order, before discount',
    DISCOUNT_PCT IS 'Discount percentage from 0 to 100 applied to this line',
    LINE_AMOUNT  IS 'Net revenue of the line in USD: quantity times unit price minus discount (generated)');

-- -----------------------------------------------------------------------------
-- Reference data
-- -----------------------------------------------------------------------------
INSERT INTO DB2INTEL_DEMO.REGION (REGION_ID, REGION_CODE, REGION_NAME, GEO) VALUES
    (1, 'NAM', 'North America',            'AMERICAS'),
    (2, 'LAT', 'Latin America',            'AMERICAS'),
    (3, 'EUR', 'Europe',                   'EMEA'),
    (4, 'MEA', 'Middle East and Africa',   'EMEA'),
    (5, 'IND', 'India',                    'APAC'),
    (6, 'APJ', 'Asia Pacific and Japan',   'APAC');

INSERT INTO DB2INTEL_DEMO.PRODUCT (PRODUCT_ID, SKU, PRODUCT_NAME, CATEGORY, UNIT_PRICE, UNIT_COST, LAUNCH_DATE, IS_ACTIVE) VALUES
    ( 1, 'SW-ANL-001', 'Analytics Workbench Standard',      'Software',              12000.00,  2400.00, '2022-03-01', 1),
    ( 2, 'SW-ANL-002', 'Analytics Workbench Enterprise',    'Software',              45000.00,  9000.00, '2022-03-01', 1),
    ( 3, 'SW-INT-001', 'Integration Hub',                   'Software',              18000.00,  4500.00, '2022-09-15', 1),
    ( 4, 'SW-SEC-001', 'Identity Guard',                    'Software',               9500.00,  1900.00, '2024-01-10', 1),
    ( 5, 'CL-CMP-001', 'Cloud Compute Reserved 1 Year',     'Cloud Services',        24000.00, 14400.00, '2022-06-01', 1),
    ( 6, 'CL-STO-001', 'Object Storage 100 TB 1 Year',      'Cloud Services',        15000.00,  8250.00, '2022-06-01', 1),
    ( 7, 'CL-DBS-001', 'Managed Database Service 1 Year',   'Cloud Services',        30000.00, 16500.00, '2023-01-15', 1),
    ( 8, 'CL-BKP-001', 'Backup and Recovery Service',       'Cloud Services',         6000.00,  2700.00, '2023-07-01', 1),
    ( 9, 'HW-SRV-001', 'Rack Server R2',                    'Hardware',               8500.00,  6375.00, '2022-02-01', 1),
    (10, 'HW-SRV-002', 'Rack Server R4 GPU',                'Hardware',              32000.00, 25600.00, '2024-04-01', 1),
    (11, 'HW-STO-001', 'Flash Storage Array 50 TB',         'Hardware',              54000.00, 41040.00, '2022-11-01', 1),
    (12, 'HW-NET-001', 'Core Network Switch',               'Hardware',               7200.00,  5040.00, '2022-02-01', 1),
    (13, 'SP-STD-001', 'Standard Support 1 Year',           'Support',                3000.00,   900.00, '2022-01-01', 1),
    (14, 'SP-PRM-001', 'Premium Support 24x7 1 Year',       'Support',                9000.00,  3150.00, '2022-01-01', 1),
    (15, 'SP-TAM-001', 'Technical Account Manager 1 Year',  'Support',               60000.00, 39000.00, '2023-05-01', 1),
    (16, 'PS-MIG-001', 'Database Migration Package',        'Professional Services', 25000.00, 17500.00, '2022-08-01', 1),
    (17, 'PS-IMP-001', 'Implementation Services 10 Days',   'Professional Services', 16000.00, 11200.00, '2022-01-01', 1),
    (18, 'PS-TRN-001', 'Administrator Training per Seat',   'Professional Services',  1800.00,   720.00, '2022-01-01', 1),
    (19, 'DA-VEC-001', 'Vector Search Add-on',              'Data and AI',           14000.00,  2800.00, '2024-11-01', 1),
    (20, 'DA-GOV-001', 'Data Governance Suite',             'Data and AI',           28000.00,  6160.00, '2024-06-01', 1),
    (21, 'DA-MLO-001', 'ML Model Ops Platform',             'Data and AI',           36000.00,  9000.00, '2024-09-01', 1),
    (22, 'DA-AST-001', 'AI Assistant Seats 25 Users',       'Data and AI',            7500.00,  2250.00, '2024-10-01', 1),
    (23, 'SW-LEG-001', 'Legacy Reporting Server',           'Software',               5000.00,  1500.00, '2019-01-01', 0),
    (24, 'HW-NET-002', 'Edge Router',                       'Hardware',               2400.00,  1680.00, '2023-03-01', 1);

-- -----------------------------------------------------------------------------
-- Customers: 240 rows. (prefix, industry) is a bijection over 30 x 8, so every
-- COMPANY_NAME is unique. Segment mix: 20% ENTERPRISE, 30% MID_MARKET, 50% SMB.
-- -----------------------------------------------------------------------------
INSERT INTO DB2INTEL_DEMO.CUSTOMER
    (CUSTOMER_ID, CUSTOMER_CODE, COMPANY_NAME, INDUSTRY, SEGMENT, REGION_ID, COUNTRY, CITY,
     CREDIT_LIMIT, CUSTOMER_SINCE, IS_ACTIVE)
WITH SEQ (N) AS (
    SELECT 1 FROM SYSIBM.SYSDUMMY1
    UNION ALL
    SELECT N + 1 FROM SEQ WHERE N < 240
),
PREFIX (IDX, WORD) AS (
    VALUES (0, 'Avenqo'), (1, 'Brelvia'), (2, 'Corvanta'), (3, 'Dravelle'), (4, 'Eskaro'),
           (5, 'Fenwyra'), (6, 'Galvori'), (7, 'Hestrel'), (8, 'Ilvanta'), (9, 'Jorvex'),
           (10, 'Kestova'), (11, 'Lumarik'), (12, 'Morvane'), (13, 'Nexquor'), (14, 'Orlenta'),
           (15, 'Pravexo'), (16, 'Quilvane'), (17, 'Rostavi'), (18, 'Selvoro'), (19, 'Tarquel'),
           (20, 'Ulvenra'), (21, 'Varnexa'), (22, 'Wexlora'), (23, 'Xantriv'), (24, 'Yorvane'),
           (25, 'Zelquor'), (26, 'Abrinth'), (27, 'Belvaro'), (28, 'Cyrenza'), (29, 'Dalvique')
),
IND (IDX, NAME, SUFFIX) AS (
    VALUES (0, 'Banking', 'Financial'), (1, 'Insurance', 'Assurance'),
           (2, 'Healthcare', 'Health'), (3, 'Retail', 'Retail Group'),
           (4, 'Manufacturing', 'Industries'), (5, 'Telecommunications', 'Networks'),
           (6, 'Energy', 'Energy'), (7, 'Logistics', 'Logistics')
),
LOC (IDX, REGION_ID, COUNTRY, CITY) AS (
    VALUES (0, 1, 'United States', 'New York'),   (1, 1, 'Canada', 'Toronto'),
           (2, 2, 'Brazil', 'Sao Paulo'),         (3, 2, 'Mexico', 'Mexico City'),
           (4, 3, 'United Kingdom', 'London'),    (5, 3, 'Germany', 'Berlin'),
           (6, 4, 'United Arab Emirates', 'Dubai'), (7, 4, 'South Africa', 'Johannesburg'),
           (8, 5, 'India', 'Bengaluru'),          (9, 5, 'India', 'Mumbai'),
           (10, 6, 'Singapore', 'Singapore'),     (11, 6, 'Japan', 'Tokyo')
)
SELECT S.N,
       'CUS-' || LPAD(TRIM(CHAR(S.N)), 5, '0'),
       P.WORD || ' ' || I.SUFFIX,
       I.NAME,
       CASE WHEN MOD(S.N, 10) < 2 THEN 'ENTERPRISE'
            WHEN MOD(S.N, 10) < 5 THEN 'MID_MARKET'
            ELSE 'SMB' END,
       L.REGION_ID, L.COUNTRY, L.CITY,
       CASE WHEN MOD(S.N, 10) < 2 THEN 500000 + MOD(S.N * 131, 11) * 50000
            WHEN MOD(S.N, 10) < 5 THEN 100000 + MOD(S.N * 131, 9) * 10000
            ELSE 15000 + MOD(S.N * 131, 8) * 2500 END,
       DATE('2021-01-01') + MOD(S.N * 53, 1400) DAYS,
       CASE WHEN MOD(S.N, 23) = 0 THEN 0 ELSE 1 END
FROM SEQ S
JOIN PREFIX P ON P.IDX = MOD(S.N - 1, 30)
JOIN IND    I ON I.IDX = (S.N - 1) / 30
JOIN LOC    L ON L.IDX = MOD(S.N * 7, 12);

-- -----------------------------------------------------------------------------
-- Orders: 3000 rows from 2025-01-01 to 2026-10-31 (data cut-off). SQRT skews
-- dates toward the recent past (growing business).
-- Customer assignment:
--   * every 4th order goes to one of the 48 ENTERPRISE accounts
--     (ids where MOD(id,10) IN (0,1): 1,10,11,20,...,240), cycling through all 48
--   * the other orders are numbered M = 1..2250 and spread evenly over all 240
--     customers (97 is coprime with 240, so each block of 240 hits every id once)
-- Status rules keep dates consistent: nothing ships after the cut-off, PENDING
-- only exists in the last month, SHIPPED (in transit) only in the last two months.
-- -----------------------------------------------------------------------------
INSERT INTO DB2INTEL_DEMO.SALES_ORDER
    (ORDER_ID, ORDER_NUMBER, CUSTOMER_ID, ORDER_DATE, SHIP_DATE, STATUS, CHANNEL)
WITH SEQ (N) AS (
    SELECT 1 FROM SYSIBM.SYSDUMMY1
    UNION ALL
    SELECT N + 1 FROM SEQ WHERE N < 3000
),
BASE (N, ORDER_DATE, RAW_STATUS) AS (
    SELECT N,
           DATE('2025-01-01') + INTEGER(669 * SQRT(DOUBLE(MOD(N * 37, 669)) / 669)) DAYS,
           CASE WHEN MOD(N, 20) = 0 THEN 'CANCELLED'
                WHEN MOD(N, 20) = 1 THEN 'RETURNED'
                WHEN MOD(N, 20) IN (2, 3) THEN 'PENDING'
                WHEN MOD(N, 20) BETWEEN 4 AND 7 THEN 'SHIPPED'
                ELSE 'DELIVERED' END
    FROM SEQ
),
STAGED (N, ORDER_DATE, SHIP_CANDIDATE, STATUS) AS (
    SELECT N, ORDER_DATE, ORDER_DATE + (1 + MOD(N, 9)) DAYS,
           CASE WHEN RAW_STATUS = 'CANCELLED' THEN 'CANCELLED'
                WHEN ORDER_DATE + (1 + MOD(N, 9)) DAYS > DATE('2026-10-31') THEN 'PENDING'
                WHEN RAW_STATUS = 'PENDING' AND ORDER_DATE >= DATE('2026-10-01') THEN 'PENDING'
                WHEN RAW_STATUS = 'PENDING' THEN 'DELIVERED'
                WHEN RAW_STATUS = 'SHIPPED' AND ORDER_DATE < DATE('2026-09-01') THEN 'DELIVERED'
                ELSE RAW_STATUS END
    FROM BASE
)
SELECT N,
       'SO-' || LPAD(TRIM(CHAR(N)), 6, '0'),
       CASE WHEN MOD(N, 4) = 0
            THEN 10 * ((MOD((N / 4) * 7, 48) + 1) / 2) + MOD(MOD((N / 4) * 7, 48) + 1, 2)
            ELSE 1 + MOD((N - N / 4) * 97, 240) END,
       ORDER_DATE,
       CASE WHEN STATUS IN ('PENDING', 'CANCELLED') THEN NULL ELSE SHIP_CANDIDATE END,
       STATUS,
       CASE WHEN MOD(N * 3, 10) < 5 THEN 'ONLINE'
            WHEN MOD(N * 3, 10) < 8 THEN 'DIRECT'
            ELSE 'PARTNER' END
FROM STAGED;

-- -----------------------------------------------------------------------------
-- Order lines: 1 to 4 per order. Product 23 (discontinued) is never sold.
-- Price is copied from the catalog. Enterprise accounts buy more and get
-- deeper discounts. LINE_AMOUNT is computed by Db2 (generated column).
-- -----------------------------------------------------------------------------
INSERT INTO DB2INTEL_DEMO.ORDER_ITEM
    (ORDER_ID, LINE_NO, PRODUCT_ID, QUANTITY, UNIT_PRICE, DISCOUNT_PCT)
WITH LINES (LINE_NO) AS (
    VALUES (1), (2), (3), (4)
),
PICK (ORDER_ID, LINE_NO, PRODUCT_ID, SEGMENT) AS (
    SELECT O.ORDER_ID, L.LINE_NO,
           CASE WHEN 1 + MOD(O.ORDER_ID * 31 + L.LINE_NO * 17, 23) = 23 THEN 24
                ELSE 1 + MOD(O.ORDER_ID * 31 + L.LINE_NO * 17, 23) END,
           C.SEGMENT
    FROM DB2INTEL_DEMO.SALES_ORDER O
    JOIN DB2INTEL_DEMO.CUSTOMER C ON C.CUSTOMER_ID = O.CUSTOMER_ID
    JOIN LINES L ON L.LINE_NO <= 1 + MOD(O.ORDER_ID * 13, 4)
)
SELECT K.ORDER_ID, K.LINE_NO, K.PRODUCT_ID,
       CASE WHEN P.UNIT_PRICE >= 20000 THEN 1 + MOD(K.ORDER_ID + K.LINE_NO * 3, 3)
            WHEN K.SEGMENT = 'ENTERPRISE' THEN 5 + MOD(K.ORDER_ID * 7 + K.LINE_NO, 26)
            ELSE 1 + MOD(K.ORDER_ID * 7 + K.LINE_NO, 10) END,
       P.UNIT_PRICE,
       CASE WHEN K.SEGMENT = 'ENTERPRISE' AND MOD(K.ORDER_ID + K.LINE_NO, 3) = 0 THEN 15.00
            WHEN MOD(K.ORDER_ID + K.LINE_NO, 10) = 1 THEN 10.00
            WHEN MOD(K.ORDER_ID + K.LINE_NO, 10) = 2 THEN 5.00
            ELSE 0.00 END
FROM PICK K
JOIN DB2INTEL_DEMO.PRODUCT P ON P.PRODUCT_ID = K.PRODUCT_ID;
