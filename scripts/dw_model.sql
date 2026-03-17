--Criação de função auxiliar e tabelas de dimensão/facto

USE HoneypotDW;
GO

-- Função de conversão de IP para inteiro (para facilitar junção com a tabela de geolite)

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

-- A FactAtaque referencia todas as dimensões via FK.
-- para evitar erros, destruir primeiro a fact e só depois as dimensões.
DROP TABLE IF EXISTS dbo.FactAtaque;
GO
DROP TABLE IF EXISTS dbo.DimData;
DROP TABLE IF EXISTS dbo.DimHost;
DROP TABLE IF EXISTS dbo.DimGeoOrigem;
DROP TABLE IF EXISTS dbo.DimASN;
DROP TABLE IF EXISTS dbo.DimProtocolo;
GO
DROP TABLE IF EXISTS dbo.stg_honeypot;
DROP TABLE IF EXISTS dbo.stg_geolite;
GO

CREATE TABLE dbo.stg_honeypot (
    datetime    VARCHAR(100)     NULL,
    host        VARCHAR(100)    NULL,
    src         VARCHAR(100)     NULL,
    srcstr      VARCHAR(100)     NULL,
    spt         VARCHAR(100)     NULL,
    dpt         VARCHAR(100)     NULL,
    proto       VARCHAR(100)     NULL,
    cc          VARCHAR(100)      NULL,
    country     VARCHAR(100)    NULL,
    locale      VARCHAR(100)    NULL,
    localeabbr  VARCHAR(100)     NULL,
    postalcode  VARCHAR(100)     NULL,
    latitude    VARCHAR(100)     NULL,
    longitude   VARCHAR(100)     NULL
);

CREATE TABLE dbo.stg_geolite (
    network                         VARCHAR(100)     NULL,
    autonomous_system_number        VARCHAR(100)     NULL,
    autonomous_system_organization  VARCHAR(500)     NULL,
    ip_start_int                    BIGINT           NULL,
    ip_end_int                      BIGINT           NULL
);



-- DIMENSÕES
CREATE TABLE dbo.DimData (
    DataID          INT         NOT NULL IDENTITY(1,1),
    DataCompleta    DATETIME    NOT NULL,
    Ano             SMALLINT    NOT NULL,
    Mes             TINYINT     NOT NULL,
    Dia             TINYINT     NOT NULL,
    Hora            TINYINT     NOT NULL,
    Minuto          TINYINT     NOT NULL,
    DiaSemana       VARCHAR(15) NOT NULL, 
    CONSTRAINT PK_DimData PRIMARY KEY (DataID)
);
GO

CREATE TABLE dbo.DimHost (
    HostID      INT             NOT NULL IDENTITY(1,1),
    NomeHost    VARCHAR(100)    NOT NULL,
    Regiao      VARCHAR(50)     NULL,
    CONSTRAINT PK_DimHost PRIMARY KEY (HostID)
);
GO

CREATE TABLE dbo.DimGeoOrigem (
    GeoOrigID       INT             NOT NULL IDENTITY(1,1),
    CodigoPais      CHAR(2)         NULL,
    NomePais        VARCHAR(100)    NULL,
    Locale          VARCHAR(100)    NULL,
    LocaleAbrev     VARCHAR(10)     NULL,
    CodigoPostal    VARCHAR(20)     NULL,
    Latitude        DECIMAL(9,6)    NULL,
    Longitude       DECIMAL(9,6)    NULL,
    CONSTRAINT PK_DimGeoOrigem PRIMARY KEY (GeoOrigID)
);
GO


CREATE TABLE dbo.DimASN (
    ASNID           INT             NOT NULL IDENTITY(1,1),
    ASNumber        INT             NULL,
    ASOrganizacao   VARCHAR(255)    NULL,
    NetworkCIDR     VARCHAR(50)     NULL,
    CONSTRAINT PK_DimASN PRIMARY KEY (ASNID)
);
GO

CREATE TABLE dbo.DimProtocolo (
    ProtoID         INT             NOT NULL IDENTITY(1,1),
    NomeProtocolo   VARCHAR(10)     NOT NULL,
    CONSTRAINT PK_DimProtocolo PRIMARY KEY (ProtoID)
);
GO




-- Tabela de Facto, FactAtaque

CREATE TABLE dbo.FactAtaque (
    AtaqueID        INT         NOT NULL IDENTITY(1,1),
    DataID          INT         NOT NULL,
    HostID          INT         NOT NULL,
    GeoOrigID       INT         NOT NULL,
    ASNID           INT         NOT NULL,
    ProtoID         INT         NOT NULL,
    PortaOrigem     INT         NULL,
    PortaDestino    INT         NULL,
    SrcIPInt        BIGINT      NULL,
    SrcIPStr        VARCHAR(45) NULL,
    CONSTRAINT PK_FactAtaque    PRIMARY KEY (AtaqueID),
    CONSTRAINT FK_Fact_Data     FOREIGN KEY (DataID)     REFERENCES dbo.DimData(DataID),
    CONSTRAINT FK_Fact_Host     FOREIGN KEY (HostID)     REFERENCES dbo.DimHost(HostID),
    CONSTRAINT FK_Fact_GeoOrig  FOREIGN KEY (GeoOrigID)  REFERENCES dbo.DimGeoOrigem(GeoOrigID),
    CONSTRAINT FK_Fact_ASN      FOREIGN KEY (ASNID)      REFERENCES dbo.DimASN(ASNID),
    CONSTRAINT FK_Fact_Proto    FOREIGN KEY (ProtoID)    REFERENCES dbo.DimProtocolo(ProtoID)
);
GO

