
USE HoneypotDW;
GO


-- FUNÇÃO AUXILIAR


IF OBJECT_ID('dbo.fn_IPtoInt', 'FN') IS NOT NULL
    DROP FUNCTION dbo.fn_IPtoInt;
GO

CREATE FUNCTION dbo.fn_IPtoInt (@ip VARCHAR(15))
RETURNS BIGINT
AS
BEGIN
    DECLARE @oct1 BIGINT, @oct2 BIGINT, @oct3 BIGINT, @oct4 BIGINT;
    DECLARE @p1 INT, @p2 INT, @p3 INT;

    SET @p1 = CHARINDEX('.', @ip, 1);
    SET @p2 = CHARINDEX('.', @ip, @p1 + 1);
    SET @p3 = CHARINDEX('.', @ip, @p2 + 1);

    SET @oct1 = CAST(LEFT(@ip, @p1 - 1) AS BIGINT);
    SET @oct2 = CAST(SUBSTRING(@ip, @p1 + 1, @p2 - @p1 - 1) AS BIGINT);
    SET @oct3 = CAST(SUBSTRING(@ip, @p2 + 1, @p3 - @p2 - 1) AS BIGINT);
    SET @oct4 = CAST(RIGHT(@ip, LEN(@ip) - @p3) AS BIGINT);

    RETURN @oct1 * 16777216 + @oct2 * 65536 + @oct3 * 256 + @oct4;
END;
GO



-- LIMPEZA 

-- Triggers primeiro
IF OBJECT_ID('dbo.trg_Insert_stg_honeypot_Checksum', 'TR') IS NOT NULL
    DROP TRIGGER dbo.trg_Insert_stg_honeypot_Checksum;
GO
IF OBJECT_ID('dbo.trg_Insert_stg_geolite_Checksum', 'TR') IS NOT NULL
    DROP TRIGGER dbo.trg_Insert_stg_geolite_Checksum;
GO
IF OBJECT_ID('dbo.trg_Insert_DimDate_Checksum', 'TR') IS NOT NULL
    DROP TRIGGER dbo.trg_Insert_DimDate_Checksum;
GO
IF OBJECT_ID('dbo.trg_Insert_DimHost_Checksum', 'TR') IS NOT NULL
    DROP TRIGGER dbo.trg_Insert_DimHost_Checksum;
GO
IF OBJECT_ID('dbo.trg_Insert_DimGeoOrigin_Checksum', 'TR') IS NOT NULL
    DROP TRIGGER dbo.trg_Insert_DimGeoOrigin_Checksum;
GO
IF OBJECT_ID('dbo.trg_Insert_DimASN_Checksum', 'TR') IS NOT NULL
    DROP TRIGGER dbo.trg_Insert_DimASN_Checksum;
GO
IF OBJECT_ID('dbo.trg_Insert_DimProtocol_Checksum', 'TR') IS NOT NULL
    DROP TRIGGER dbo.trg_Insert_DimProtocol_Checksum;
GO

-- Stored Procedure
IF OBJECT_ID('dbo.sp_Populate_ASN_Lookup', 'P') IS NOT NULL
    DROP PROCEDURE dbo.sp_Populate_ASN_Lookup;
GO

-- Facto
DROP TABLE IF EXISTS dbo.FactAttack;
GO

-- Dimensões
DROP TABLE IF EXISTS dbo.DimDate;
DROP TABLE IF EXISTS dbo.DimHost;
DROP TABLE IF EXISTS dbo.DimGeoOrigin;
DROP TABLE IF EXISTS dbo.DimASN;
DROP TABLE IF EXISTS dbo.DimProtocol;
GO

-- Staging
DROP TABLE IF EXISTS dbo.stg_honeypot;
DROP TABLE IF EXISTS dbo.stg_geolite;
GO

-- Audit
DROP TABLE IF EXISTS dbo.DW_Audit;
GO

--Lookup
DROP TABLE IF EXISTS dbo.stg_asn_lookup;




-- TABELA DE AUDIT


SET ANSI_NULLS ON;
GO
SET QUOTED_IDENTIFIER ON;
GO

CREATE TABLE dbo.DW_Audit (
    run_id              VARCHAR(50)     NOT NULL,
    start_on            DATETIME        NOT NULL,
    end_on              DATETIME        NULL,
    name                VARCHAR(50)     NOT NULL,
    success_row_count   INT             NULL,
    failed_row_count    INT             NULL,
    execution_status    VARCHAR(20)     NOT NULL,
    CONSTRAINT PK_DW_Audit PRIMARY KEY CLUSTERED (run_id ASC)
);
GO



-- STAGING TABLES


CREATE TABLE dbo.stg_honeypot (
    stg_id                  INT             NOT NULL IDENTITY(1,1),
    datetime                DATETIME        NULL,
    host                    VARCHAR(100)    NULL,
    src                     BIGINT          NULL,
    srcstr                  VARCHAR(45)     NULL,
    spt                     INT             NULL,
    dpt                     INT             NULL,
    proto                   VARCHAR(10)     NULL,
    cc                      CHAR(2)         NULL,
    country                 VARCHAR(100)    NULL,
    locale                  VARCHAR(100)    NULL,
    localeabbr              VARCHAR(10)     NULL,
    postalcode              VARCHAR(20)     NULL,
    latitude                DECIMAL(9,6)    NULL,
    longitude               DECIMAL(9,6)    NULL,
    -- Checksum (um por dimensão que esta staging alimenta)
    DW_row_checksum_date    VARCHAR(64)     NULL,
    DW_row_checksum_host    VARCHAR(64)     NULL,
    DW_row_checksum_geo     VARCHAR(64)     NULL,
    DW_row_checksum_proto   VARCHAR(64)     NULL,
    -- Audit
    DW_run_id               VARCHAR(50)     NULL,
    DW_updated_on           DATETIME        NULL,
    DW_source_system        VARCHAR(100)    NULL
);
GO

CREATE TABLE dbo.stg_geolite (
    stg_id                          INT             NOT NULL IDENTITY(1,1),
    network                         VARCHAR(50)     NULL,
    autonomous_system_number        INT             NULL,
    autonomous_system_organization  VARCHAR(255)    NULL,
    ip_start_int                    BIGINT          NULL,
    ip_end_int                      BIGINT          NULL,
    -- Checksum
    DW_row_checksum_asn             VARCHAR(64)     NULL,
    -- Audit
    DW_run_id                       VARCHAR(50)     NULL,
    DW_updated_on                   DATETIME        NULL,
    DW_source_system                VARCHAR(100)    NULL
);
GO


--Tabela de lookup para otimizar a busca do ASNID na FactAttack
CREATE TABLE dbo.stg_asn_lookup (
    src     BIGINT      NOT NULL,
    ASNID   INT         NOT NULL
);



-- DIMENSÕES


CREATE TABLE dbo.DimDate (
    DateID              INT             NOT NULL IDENTITY(1,1),
    FullDate            DATETIME        NOT NULL,
    Year                SMALLINT        NOT NULL,
    Month               TINYINT         NOT NULL,
    Day                 TINYINT         NOT NULL,
    Hour                TINYINT         NOT NULL,
    Minute              TINYINT         NOT NULL,
    WeekDay             VARCHAR(15)     NOT NULL,
    -- Checksum + Audit
    DW_row_checksum     VARCHAR(64)     NULL,
    DW_run_id           VARCHAR(50)     NULL,
    DW_updated_on       DATETIME        NULL,
    DW_source_system    VARCHAR(100)    NULL,
    CONSTRAINT PK_DimDate PRIMARY KEY (DateID)
);
GO

CREATE TABLE dbo.DimHost (
    HostID              INT             NOT NULL IDENTITY(1,1),
    HostName            VARCHAR(100)    NOT NULL,
    Region              VARCHAR(50)     NULL,
    -- Checksum + Audit
    DW_row_checksum     VARCHAR(64)     NULL,
    DW_run_id           VARCHAR(50)     NULL,
    DW_updated_on       DATETIME        NULL,
    DW_source_system    VARCHAR(100)    NULL,
    CONSTRAINT PK_DimHost PRIMARY KEY (HostID)
);
GO

CREATE TABLE dbo.DimGeoOrigin (
    GeoOrigID           INT             NOT NULL IDENTITY(1,1),
    CountryCode         CHAR(2)         NULL,
    Country             VARCHAR(100)    NULL,
    Locale              VARCHAR(100)    NULL,
    LocaleAbrev         VARCHAR(10)     NULL,
    PostalCode          VARCHAR(20)     NULL,
    Latitude            DECIMAL(9,6)    NULL,
    Longitude           DECIMAL(9,6)    NULL,
    -- Checksum + Audit
    DW_row_checksum     VARCHAR(64)     NULL,
    DW_run_id           VARCHAR(50)     NULL,
    DW_updated_on       DATETIME        NULL,
    DW_source_system    VARCHAR(100)    NULL,
    CONSTRAINT PK_DimGeoOrigin PRIMARY KEY (GeoOrigID)
);
GO

CREATE TABLE dbo.DimASN (
    ASNID               INT             NOT NULL IDENTITY(1,1),
    ASNumber            INT             NULL,
    ASOrganization      VARCHAR(255)    NULL,
    NetworkCIDR         VARCHAR(50)     NULL,
    -- Checksum + Audit
    DW_row_checksum     VARCHAR(64)     NULL,
    DW_run_id           VARCHAR(50)     NULL,
    DW_updated_on       DATETIME        NULL,
    DW_source_system    VARCHAR(100)    NULL,
    CONSTRAINT PK_DimASN PRIMARY KEY (ASNID)
);
GO

--Valor Unknown do ASN para registos sem correspondência
SET IDENTITY_INSERT dbo.DimASN ON;
INSERT INTO dbo.DimASN (ASNID, ASNumber, ASOrganization, NetworkCIDR,
                        DW_row_checksum, DW_run_id, DW_updated_on, DW_source_system)
VALUES (-1, NULL, 'Unknown', NULL, NULL, NULL, NULL, NULL);
SET IDENTITY_INSERT dbo.DimASN OFF;
GO

CREATE TABLE dbo.DimProtocol (
    ProtoID             INT             NOT NULL IDENTITY(1,1),
    ProtocolName        VARCHAR(10)     NOT NULL,
    -- Checksum + Audit
    DW_row_checksum     VARCHAR(64)     NULL,
    DW_run_id           VARCHAR(50)     NULL,
    DW_updated_on       DATETIME        NULL,
    DW_source_system    VARCHAR(100)    NULL,
    CONSTRAINT PK_DimProtocol PRIMARY KEY (ProtoID)
);
GO


-- TABELA DE FACTO (sem checksum, com audit)

CREATE TABLE dbo.FactAttack (
    AttackID            INT             NOT NULL IDENTITY(1,1),
    DateID              INT             NOT NULL,
    HostID              INT             NOT NULL,
    GeoOrigID           INT             NOT NULL,
    ASNID               INT             NOT NULL,
    ProtoID             INT             NOT NULL,
    SrcPort             INT             NULL,
    DestPort            INT             NULL,
    SrcIPInt            BIGINT          NULL,
    SrcIPStr            VARCHAR(45)     NULL,
    -- Audit
    DW_run_id           VARCHAR(50)     NULL,
    DW_updated_on       DATETIME        NULL,
    DW_source_system    VARCHAR(100)    NULL,
    CONSTRAINT PK_FactAttack    PRIMARY KEY (AttackID),
    CONSTRAINT FK_Fact_Date     FOREIGN KEY (DateID)     REFERENCES dbo.DimDate(DateID),
    CONSTRAINT FK_Fact_Host     FOREIGN KEY (HostID)     REFERENCES dbo.DimHost(HostID),
    CONSTRAINT FK_Fact_GeoOrig  FOREIGN KEY (GeoOrigID)  REFERENCES dbo.DimGeoOrigin(GeoOrigID),
    CONSTRAINT FK_Fact_ASN      FOREIGN KEY (ASNID)      REFERENCES dbo.DimASN(ASNID),
    CONSTRAINT FK_Fact_Proto    FOREIGN KEY (ProtoID)     REFERENCES dbo.DimProtocol(ProtoID)
);
GO



-- TRIGGERS DE CHECKSUM NAS STAGING TABLES

CREATE TRIGGER dbo.trg_Insert_stg_honeypot_Checksum
ON dbo.stg_honeypot
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE t
    SET
        t.DW_row_checksum_date = CONVERT(VARCHAR(64),
            HASHBYTES('MD5', CONCAT(
                ISNULL(CONVERT(VARCHAR(23), t.datetime, 121), ''),
                ''
            )), 2),

        t.DW_row_checksum_host = CONVERT(VARCHAR(64),
            HASHBYTES('MD5', CONCAT(
                ISNULL(t.host, ''),
                ''
            )), 2),

        t.DW_row_checksum_geo = CONVERT(VARCHAR(64),
            HASHBYTES('MD5', CONCAT(
                ISNULL(t.cc, ''),
                ISNULL(t.country, ''),
                ISNULL(t.locale, ''),
                ISNULL(t.localeabbr, ''),
                ISNULL(t.postalcode, ''),
                ISNULL(CAST(t.latitude AS VARCHAR(20)), ''),
                ISNULL(CAST(t.longitude AS VARCHAR(20)), '')
            )), 2),

        t.DW_row_checksum_proto = CONVERT(VARCHAR(64),
            HASHBYTES('MD5', CONCAT(
                ISNULL(t.proto, ''),
                ''
            )), 2)
    FROM dbo.stg_honeypot t
INNER JOIN inserted i ON t.stg_id = i.stg_id;
END;
GO


CREATE TRIGGER dbo.trg_Insert_stg_geolite_Checksum
ON dbo.stg_geolite
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE t
    SET
        t.DW_row_checksum_asn = CONVERT(VARCHAR(64),
            HASHBYTES('MD5', CONCAT(
                ISNULL(CAST(t.autonomous_system_number AS VARCHAR(20)), ''),
                ISNULL(t.autonomous_system_organization, ''),
                ISNULL(t.network, '')
            )), 2)
    FROM dbo.stg_geolite t
INNER JOIN inserted i ON t.stg_id = i.stg_id;
END;
GO



-- TRIGGERS DE CHECKSUM NAS DIMENSÕES


CREATE TRIGGER dbo.trg_Insert_DimDate_Checksum
ON dbo.DimDate
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE t
    SET t.DW_row_checksum = CONVERT(VARCHAR(64),
        HASHBYTES('MD5', CONCAT(
            ISNULL(CONVERT(VARCHAR(23), t.FullDate, 121), ''),
                ''
            )), 2)
    FROM dbo.DimDate t
    INNER JOIN inserted i ON t.DateID = i.DateID;
END;
GO


CREATE TRIGGER dbo.trg_Insert_DimHost_Checksum
ON dbo.DimHost
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE t
    SET t.DW_row_checksum = CONVERT(VARCHAR(64),
        HASHBYTES('MD5', CONCAT(
            ISNULL(t.HostName, ''),
            ISNULL(t.Region, '')
        )), 2)
    FROM dbo.DimHost t
    INNER JOIN inserted i ON t.HostID = i.HostID;
END;
GO


CREATE TRIGGER dbo.trg_Insert_DimGeoOrigin_Checksum
ON dbo.DimGeoOrigin
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE t
    SET t.DW_row_checksum = CONVERT(VARCHAR(64),
        HASHBYTES('MD5', CONCAT(
            ISNULL(t.CountryCode, ''),
            ISNULL(t.Country, ''),
            ISNULL(t.Locale, ''),
            ISNULL(t.LocaleAbrev, ''),
            ISNULL(t.PostalCode, ''),
            ISNULL(CAST(t.Latitude AS VARCHAR(20)), ''),
            ISNULL(CAST(t.Longitude AS VARCHAR(20)), '')
        )), 2)
    FROM dbo.DimGeoOrigin t
    INNER JOIN inserted i ON t.GeoOrigID = i.GeoOrigID;
END;
GO


CREATE TRIGGER dbo.trg_Insert_DimASN_Checksum
ON dbo.DimASN
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE t
    SET t.DW_row_checksum = CONVERT(VARCHAR(64),
        HASHBYTES('MD5', CONCAT(
            ISNULL(CAST(t.ASNumber AS VARCHAR(20)), ''),
            ISNULL(t.ASOrganization, ''),
            ISNULL(t.NetworkCIDR, '')
        )), 2)
    FROM dbo.DimASN t
    INNER JOIN inserted i ON t.ASNID = i.ASNID;
END;
GO


CREATE TRIGGER dbo.trg_Insert_DimProtocol_Checksum
ON dbo.DimProtocol
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE t
    SET t.DW_row_checksum = CONVERT(VARCHAR(64),
        HASHBYTES('MD5', CONCAT(
            ISNULL(t.ProtocolName, ''),
            ''
        )), 2)
    FROM dbo.DimProtocol t
    INNER JOIN inserted i ON t.ProtoID = i.ProtoID;
END;
GO

-- STORED PROCEDURE
CREATE PROCEDURE dbo.sp_Populate_ASN_Lookup
AS
BEGIN
    SET NOCOUNT ON;
 
    INSERT INTO dbo.stg_asn_lookup (src, ASNID)
    SELECT u.src, ISNULL(a.ASNID, -1)
    FROM (SELECT DISTINCT src FROM dbo.stg_honeypot WHERE src IS NOT NULL) u
    OUTER APPLY (
        SELECT TOP 1 g.network
        FROM dbo.stg_geolite g
        WHERE u.src BETWEEN g.ip_start_int AND g.ip_end_int
        ORDER BY g.ip_start_int DESC
    ) g
    LEFT JOIN dbo.DimASN a ON a.NetworkCIDR = g.network;
END;
GO