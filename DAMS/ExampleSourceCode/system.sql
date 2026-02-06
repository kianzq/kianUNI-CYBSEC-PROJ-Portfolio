-------------------------------------------------------------------DAMS ---------------------------------------------------------
--------------------------------------------------------------CREATE TABLES ---------------------------------------------------------
CREATE DATABASE DAMS;
USE DAMS;

--Original DAMS schema
--Table: Agents
CREATE TABLE Agents ( 
    AgentID INT IDENTITY(1,1) PRIMARY KEY, 
    Name NVARCHAR(100) NOT NULL, 
    Email NVARCHAR(100), 
    Phone NVARCHAR(20), 
    Address NVARCHAR(255), 
    Status NVARCHAR(20) DEFAULT 'Active', 
    CreatedAt DATETIME DEFAULT GETDATE() 
); 

INSERT INTO Agents (Name, Email, Phone, Address)
VALUES
--REDACTED--

--Table: Products
CREATE TABLE Products ( 
    ProductID INT IDENTITY(1,1) PRIMARY KEY, 
    Name NVARCHAR(100) NOT NULL, 
    Description NVARCHAR(255), 
    Price DECIMAL(10,2) NOT NULL, 
    CreatedAt DATETIME DEFAULT GETDATE() 
); 

INSERT INTO Products (Name, Description, Price)
VALUES
--REDACTED--

--Table: Sales
CREATE TABLE Sales ( 
    SaleID INT IDENTITY(1,1) PRIMARY KEY, 
    AgentID INT NOT NULL, 
    ProductID INT NOT NULL, 
    Quantity INT NOT NULL, 
    --TotalAmount AS (Quantity * (SELECT Price FROM Products WHERE Products.ProductID = Sales.ProductID)) PERSISTED, 
	TotalAmount DECIMAL(10,2) NOT NULL,
    SaleDate DATETIME DEFAULT GETDATE(), 
    FOREIGN KEY(AgentID) REFERENCES Agents(AgentID), 
    FOREIGN KEY(ProductID) REFERENCES Products(ProductID) 
); 

INSERT INTO Sales (AgentID, ProductID, Quantity, TotalAmount)
VALUES
--REDACTED--

--Table: Commision
CREATE TABLE Commission ( 
	CommissionID INT IDENTITY(1,1) PRIMARY KEY, 
	AgentID INT NOT NULL, 
	SaleID INT NOT NULL, 
	CommissionRate DECIMAL(5,2) NOT NULL, -- e.g., 5.00 for 5% 
	-- CommissionAmount AS ((SELECT TotalAmount FROM Sales WHERE Sales.SaleID = Commission.SaleID) *CommissionRate / 100.0) PERSISTED, 
	CommissionAmount DECIMAL(10,2) NOT NULL,
	CreatedAt DATETIME DEFAULT GETDATE(), 
	FOREIGN KEY(AgentID) REFERENCES Agents(AgentID), 
	FOREIGN KEY(SaleID) REFERENCES Sales(SaleID) 
); 

INSERT INTO Commission (AgentID, SaleID, CommissionRate, CommissionAmount)
SELECT 
    AgentID,
    SaleID,
    5.00 AS CommissionRate,
    TotalAmount * 5.00 / 100.0 AS CommissionAmount
FROM Sales;

--Table: User_Agent
CREATE TABLE User_Agent (
    UserID INT PRIMARY KEY IDENTITY(1,1),
    AgentID INT FOREIGN KEY REFERENCES Agents(AgentID),
    Username NVARCHAR(100) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(256) NOT NULL,
    Role NVARCHAR(50) DEFAULT 'Agent'
);

CREATE TRIGGER trg_HashPassword_OnInsert
ON User_Agent
INSTEAD OF INSERT
AS
BEGIN
    INSERT INTO User_Agent (AgentID, Username, PasswordHash, Role)
    SELECT 
        AgentID,
        Username,
        CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(100), PasswordHash)), 2),
        ISNULL(Role, 'Agent')
    FROM inserted;
END;

INSERT INTO User_Agent (AgentID, Username, PasswordHash)
VALUES 
--REDACTED--

--Table: Employee (for details) --*
CREATE TABLE Employee (
    EmployeeID INT PRIMARY KEY IDENTITY(1001,1),
    FullName NVARCHAR(100) NOT NULL,
    Email NVARCHAR(100) UNIQUE NOT NULL,
    Phone NVARCHAR(20),
    Address NVARCHAR(255),
    Department NVARCHAR(50),  -- e.g., 'DBA', 'Marketing', etc.
    IsActive BIT DEFAULT 1
);

INSERT INTO Employee (FullName, Email, Phone, Address, Department, IsActive)
VALUES
--REDATED--
  
--Table: User_Employee (for credentials etc) --*
CREATE TABLE User_Employee (
    UserID INT PRIMARY KEY IDENTITY(1,1),
    EmployeeID INT FOREIGN KEY REFERENCES Employee(EmployeeID),
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,
    Role NVARCHAR(50) NOT NULL, -- e.g., 'role_dba', 'role_marketing'
    CreatedAt DATETIME DEFAULT GETDATE(),
    LastLogin DATETIME,
    IsLocked BIT DEFAULT 0,
	PasswordSalt NVARCHAR(50) NOT NULL DEFAULT NEWID()
);

CREATE OR ALTER TRIGGER trg_HashPassword_OnInsert_Employee
ON User_Employee
INSTEAD OF INSERT
AS
BEGIN
    INSERT INTO User_Employee (EmployeeID, Username, PasswordHash, Role, PasswordSalt, CreatedAt, LastLogin, IsLocked)
    SELECT 
        EmployeeID,
        Username,
        CONVERT(NVARCHAR(128), HASHBYTES('SHA2_512', CONVERT(VARCHAR(100), PasswordHash + PasswordSalt)), 2),
        Role,
        ISNULL(PasswordSalt, NEWID()),
        ISNULL(CreatedAt, GETDATE()),
        LastLogin,
        ISNULL(IsLocked, 0)
    FROM inserted;
END;

DECLARE @salt1 NVARCHAR(50) = NEWID();
DECLARE @salt2 NVARCHAR(50) = NEWID();
DECLARE @salt3 NVARCHAR(50) = NEWID();
DECLARE @salt4 NVARCHAR(50) = NEWID();
DECLARE @salt5 NVARCHAR(50) = NEWID();

-- Insert plaintext password only
INSERT INTO User_Employee (EmployeeID, Username, PasswordHash, Role, PasswordSalt, CreatedAt, IsLocked)
VALUES
--REDACTED--

----------------------------------------------------------------CREATE LOGIN, ROLE, USER ---------------------------------------------------------
-- DB admin
CREATE LOGIN login_dba WITH PASSWORD = 'StrongPass#2025!', DEFAULT_DATABASE = DAMS;
CREATE USER user_dba FOR LOGIN login_dba;
CREATE ROLE role_dba;
ALTER ROLE role_dba ADD MEMBER user_dba;

-- Analytics
CREATE LOGIN login_analytics WITH PASSWORD = 'StrongPass#2025!', DEFAULT_DATABASE = DAMS;
CREATE USER user_analytics FOR LOGIN login_analytics;
CREATE ROLE role_analytics;
ALTER ROLE role_analytics ADD MEMBER user_analytics;

-- Marketing
CREATE LOGIN login_marketing WITH PASSWORD = 'StrongPass#2025!', DEFAULT_DATABASE = DAMS;
CREATE USER user_marketing FOR LOGIN login_marketing;
CREATE ROLE role_marketing;
ALTER ROLE role_marketing ADD MEMBER user_marketing;

-- Portal Development
CREATE LOGIN login_portaldev WITH PASSWORD = 'StrongPass#2025!', DEFAULT_DATABASE = DAMS;
CREATE USER user_portaldev FOR LOGIN login_portaldev;
CREATE ROLE role_portaldev;
ALTER ROLE role_portaldev ADD MEMBER user_portaldev;

--IT admin
CREATE LOGIN login_it_admin WITH PASSWORD = 'StrongPass#2025!', DEFAULT_DATABASE = DAMS;
CREATE USER user_it_admin FOR LOGIN login_it_admin;
CREATE ROLE role_it_admin;
ALTER ROLE role_it_admin ADD MEMBER user_it_admin;


-- Agent / User
CREATE LOGIN login_agent WITH PASSWORD = 'SecureStrong#Password123', DEFAULT_DATABASE = DAMS;
CREATE USER user_agent FOR LOGIN login_agent;
CREATE ROLE role_agent;
ALTER ROLE role_agent ADD MEMBER user_agent;

---------------------------------------------------------------- CREATE VIEW ---------------------------------------------------------
-- Agents (hide Email, Phone, Address)
CREATE VIEW v_Agents_Analytics AS
SELECT 
    AgentID,
    Name,
    Status,
    CreatedAt
FROM Agents;

-- Agents (mask Email, Phone) (hide Address)
CREATE VIEW v_Agents_Masked AS
SELECT 
    AgentID,
    Name,
    LEFT(Email, 2) + '*****@****.com' AS Email,
    'XXXX-XXXX-' + RIGHT(Phone, 4) AS Phone,
    Status
FROM Agents;

-- Commission (hide CommissionRate)
CREATE VIEW v_Commission_Analytics AS
SELECT 
    CommissionID,
    AgentID,
    SaleID,
    CommissionAmount,
    CreatedAt 
FROM Commission;

-- Agents (activate, deactivate agent)
CREATE VIEW v_AgentStatus_Update AS
SELECT 
    AgentID,
    Status
FROM Agents;

-- Agents (update PII)
CREATE VIEW v_AgentPII_Update AS
SELECT 
    AgentID,
    Email,
    Phone
FROM Agents;

-- Product (update price)
CREATE VIEW v_ProductPrice_Update AS
SELECT 
    ProductID,
    Price
FROM Products;

-- Agent: view their details
CREATE VIEW v_MyAgentProfile AS SELECT AgentID, Name, Email, Phone, Address, Status FROM Agents;
CREATE VIEW v_MySales AS SELECT * FROM Sales;
CREATE VIEW v_MyCommission AS SELECT * FROM Commission;
CREATE VIEW v_MyLoginDetails AS SELECT Username, PasswordHash FROM User_Agent;

-- Employee: View their details --*
CREATE VIEW v_MyEmployeeProfile AS
SELECT 
    e.EmployeeID,
    e.FullName,
    e.Email,
    e.Phone,
    e.Address,
    e.Department,
    e.IsActive
FROM Employee e
WHERE e.EmployeeID = CAST(SESSION_CONTEXT(N'EmployeeID') AS INT);

CREATE VIEW v_MyEmployeeLoginDetails AS
SELECT 
    ue.Username,
    ue.PasswordHash,
    ue.Role
FROM User_Employee ue
WHERE ue.EmployeeID = CAST(SESSION_CONTEXT(N'EmployeeID') AS INT);

---------------------------------------------------------------- CREATE STORED PROCEDURE ---------------------------------------------------------
-- DB Admin: add new agent & login
CREATE PROCEDURE sp_AddAgentWithLogin
    @Name NVARCHAR(100),
    @Email NVARCHAR(100),
    @Phone NVARCHAR(20),
    @Address NVARCHAR(255),
    @Username NVARCHAR(100),
    @PlainPassword NVARCHAR(100),
    @Role NVARCHAR(50) = 'Agent'
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_validateEmployeeSession;

    INSERT INTO Agents (Name, Email, Phone, Address)
    VALUES (@Name, @Email, @Phone, @Address);

    DECLARE @NewAgentID INT = SCOPE_IDENTITY();

	INSERT INTO [User] (AgentID, Username, PasswordHash, Role)
	VALUES (
		@NewAgentID,
		@Username,
		@PlainPassword, -- trigger will hash this
		@Role
	);
END;

-- DB Admin: add new employee & login --*
CREATE OR ALTER PROCEDURE sp_AddEmployeeWithLogin
    @FullName NVARCHAR(100),
    @Email NVARCHAR(100),
    @Phone NVARCHAR(20),
    @Address NVARCHAR(255),
    @Department NVARCHAR(50),
    @Username NVARCHAR(50),
    @PlainPassword NVARCHAR(100),
    @Role NVARCHAR(50)
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_validateEmployeeSession;

    INSERT INTO Employee (FullName, Email, Phone, Address, Department)
    VALUES (@FullName, @Email, @Phone, @Address, @Department);

    DECLARE @NewEmployeeID INT = SCOPE_IDENTITY();

    INSERT INTO User_Employee (EmployeeID, Username, PasswordHash, Role)
    VALUES (
        @NewEmployeeID,
        @Username,
        @PlainPassword,
        @Role
    );
END;

-- add new product
CREATE OR ALTER PROCEDURE sp_AddProduct
    @Name NVARCHAR(100),
    @Description NVARCHAR(255),
    @Price DECIMAL(10,2)
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_validateEmployeeSession;

    INSERT INTO Products (Name, Description, Price)
    VALUES (@Name, @Description, @Price);
END;

-- Sales
-- insert sale
CREATE OR ALTER PROCEDURE sp_InsertSale
    @AgentID INT,
    @ProductID INT,
    @Quantity INT
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_validateEmployeeSession;

    DECLARE @Price DECIMAL(10,2);
    DECLARE @TotalAmount DECIMAL(10,2);

    SELECT @Price = Price
    FROM Products
    WHERE ProductID = @ProductID;

    IF @Price IS NULL
    BEGIN
        THROW 50010, 'Invalid ProductID: Product not found.', 1;
    END

    SET @TotalAmount = @Price * @Quantity;

    INSERT INTO Sales (AgentID, ProductID, Quantity, TotalAmount)
    VALUES (@AgentID, @ProductID, @Quantity, @TotalAmount);

    PRINT 'New sale has been recorded successfully.';
    PRINT 'Details: AgentID = ' + CAST(@AgentID AS NVARCHAR)
        + ', ProductID = ' + CAST(@ProductID AS NVARCHAR)
        + ', Quantity = ' + CAST(@Quantity AS NVARCHAR)
        + ', Total = RM' + CAST(@TotalAmount AS NVARCHAR);
END;
	-------------------------------- Create Trigger ---------------------------------
	-- Insert new Commission
	-- Auto update new Sales and Commission based on Sales.TotalAmount
	--(Sales under RM100 → 3% 
	-- RM100–RM500 → 5% 
	-- RM500 and above → 8%) 
CREATE TRIGGER trg_AfterInsert_Sales
ON Sales
AFTER INSERT
AS
BEGIN
    INSERT INTO Commission (AgentID, SaleID, CommissionRate, CommissionAmount, CreatedAt)
    SELECT 
        i.AgentID,
        i.SaleID,
        CASE
            WHEN i.TotalAmount < 100 THEN 3.00
            WHEN i.TotalAmount BETWEEN 100 AND 500 THEN 5.00
            ELSE 8.00
        END AS CommissionRate,
        i.TotalAmount * 
        CASE
            WHEN i.TotalAmount < 100 THEN 3.00
            WHEN i.TotalAmount BETWEEN 100 AND 500 THEN 5.00
            ELSE 8.00
        END / 100.0 AS CommissionAmount,
        GETDATE()
    FROM inserted i;
END;

-- admin reset password for agent
CREATE OR ALTER PROCEDURE sp_AdminResetPassword
    @Username NVARCHAR(100),
    @NewPlainPassword NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_validateEmployeeSession;

    IF NOT EXISTS (SELECT 1 FROM User_Agent WHERE Username = @Username)
    BEGIN
        THROW 50002, 'User not found.', 1;
    END

    DECLARE @NewHash NVARCHAR(64) = CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(100), @NewPlainPassword)), 2);
    
	UPDATE User_Agent
    SET PasswordHash = @NewHash
    WHERE Username = @Username;

    PRINT 'Password reset successfully. Notify user to change password on next login.';
END;

-- admin reset password for employee
CREATE OR ALTER PROCEDURE sp_AdminResetPassword_Employee
    @Username NVARCHAR(50),
    @NewPlainPassword NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_validateEmployeeSession;

    IF NOT EXISTS (SELECT 1 FROM User_Employee WHERE Username = @Username)
    BEGIN
        THROW 50002, 'User not found.', 1;
    END

    DECLARE @NewSalt NVARCHAR(50) = NEWID();

    DECLARE @NewHash NVARCHAR(128) = CONVERT(NVARCHAR(128), HASHBYTES('SHA2_512', CONVERT(VARCHAR(100), @NewPlainPassword + @NewSalt)), 2);

    UPDATE User_Employee
    SET PasswordHash = @NewHash,
        PasswordSalt = @NewSalt
    WHERE Username = @Username;

    PRINT 'Employee password reset successfully. Notify user to change password on next login.';
END;

-- sp Agent Change Password (validate oldPassword)
CREATE or ALTER PROCEDURE sp_ChangePassword
    @Username NVARCHAR(100),
    @OldPassword NVARCHAR(100),
    @NewPassword NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

	BEGIN TRY
		EXEC sp_ValidateSession;
	END TRY
	BEGIN CATCH
		DECLARE @SessionID INT = CAST(SESSION_CONTEXT(N'SessionID') AS INT);
		IF @SessionID IS NOT NULL
		BEGIN
			EXEC sp_LogoutAgent @SessionID;
		END;
		THROW;
	END CATCH

    DECLARE @OldHash NVARCHAR(64) = CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(100), @OldPassword)), 2);
    DECLARE @NewHash NVARCHAR(64) = CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(100), @NewPassword)), 2);

    IF EXISTS (
        SELECT 1 FROM User_Agent
        WHERE Username = @Username AND PasswordHash = @OldHash
    )
    BEGIN
        UPDATE User_Agent
        SET PasswordHash = @NewHash
        WHERE Username = @Username;

        PRINT 'Password updated successfully.';
    END
    ELSE
    BEGIN
        PRINT 'Invalid username or old password.';
    END
END;

-- sp Employee Change Password (validate oldPassword) --*
CREATE OR ALTER PROCEDURE sp_EmployeeChangePassword
    @Username NVARCHAR(100),
    @OldPassword NVARCHAR(100),
    @NewPassword NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_validateEmployeeSession;

    DECLARE @StoredSalt NVARCHAR(50);
    DECLARE @StoredHash NVARCHAR(128);

    SELECT 
        @StoredSalt = PasswordSalt,
        @StoredHash = PasswordHash
    FROM User_Employee
    WHERE Username = @Username;

    IF @StoredSalt IS NULL OR @StoredHash IS NULL
    BEGIN
        PRINT 'Invalid username.';
        RETURN;
    END

    DECLARE @OldHash NVARCHAR(128) = CONVERT(NVARCHAR(128), HASHBYTES('SHA2_512', CONVERT(VARCHAR(100), @OldPassword + @StoredSalt)), 2);

    IF @OldHash = @StoredHash
    BEGIN
        DECLARE @NewSalt NVARCHAR(50) = NEWID();
        DECLARE @NewHash NVARCHAR(128) = CONVERT(NVARCHAR(128), HASHBYTES('SHA2_512', CONVERT(VARCHAR(100), @NewPassword + @NewSalt)), 2);

        UPDATE User_Employee
        SET PasswordHash = @NewHash,
            PasswordSalt = @NewSalt
        WHERE Username = @Username;

        PRINT 'Password changed successfully.';
    END
    ELSE
    BEGIN
        PRINT 'Old password is incorrect.';
    END
END;



-- SP Agent Change Username
CREATE or ALTER PROCEDURE sp_ChangeUsername
    @OldUsername NVARCHAR(100),
    @Password NVARCHAR(100),
    @NewUsername NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

	BEGIN TRY
		EXEC sp_ValidateSession;
	END TRY
	BEGIN CATCH
		DECLARE @SessionID INT = CAST(SESSION_CONTEXT(N'SessionID') AS INT);
		IF @SessionID IS NOT NULL
		BEGIN
			EXEC sp_LogoutAgent @SessionID;
		END;

		THROW
	END CATCH;

    DECLARE @Hash NVARCHAR(64) = CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(100), @Password)), 2);

    DECLARE @UserID INT;
    SELECT @UserID = UserID
    FROM User_Agent
    WHERE Username = @OldUsername AND PasswordHash = @Hash;

    IF @UserID IS NULL
    BEGIN
        PRINT 'Invalid username or password.';
        RETURN;
    END

    IF EXISTS (SELECT 1 FROM User_Agent WHERE Username = @NewUsername)
    BEGIN
        PRINT 'New username is already in use.';
        RETURN;
    END

    UPDATE User_Agent
    SET Username = @NewUsername
    WHERE UserID = @UserID;

    PRINT 'Username updated successfully.';
END;

-- SP Employee Change Username --*
CREATE OR ALTER PROCEDURE sp_EmployeeChangeUsername
    @OldUsername NVARCHAR(100),
    @Password NVARCHAR(100),
    @NewUsername NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;
    EXEC sp_validateEmployeeSession;

    DECLARE @Hash NVARCHAR(64) = CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(100), @Password)), 2);

    DECLARE @UserID INT;
    SELECT @UserID = UserID
    FROM User_Employee
    WHERE Username = @OldUsername AND PasswordHash = @Hash;

    IF @UserID IS NULL
    BEGIN
        PRINT 'Invalid username or password.';
        RETURN;
    END

    IF EXISTS (SELECT 1 FROM User_Employee WHERE Username = @NewUsername)
    BEGIN
        PRINT 'New username is already in use.';
        RETURN;
    END

    UPDATE User_Employee
    SET Username = @NewUsername
    WHERE UserID = @UserID;

    PRINT 'Username updated successfully.';
END;

CREATE OR ALTER PROCEDURE sp_GetMyAgentProfile
AS
BEGIN
    SET NOCOUNT ON;

	BEGIN TRY
		EXEC sp_ValidateSession;
	END TRY
	BEGIN CATCH
		DECLARE @SessionID INT = CAST(SESSION_CONTEXT(N'SessionID') AS INT);
		IF @SessionID IS NOT NULL
		BEGIN
			EXEC sp_LogoutAgent @SessionID;
		END;

		THROW
	END CATCH;

    SELECT a.AgentID, a.Name, a.Email, a.Phone, a.Address, a.Status
    FROM Agents a
    JOIN AgentSession s ON a.AgentID = s.AgentID
    WHERE s.SessionID = @SessionID;
END;

CREATE OR ALTER PROCEDURE sp_GetMySales
AS
BEGIN
    SET NOCOUNT ON;

	BEGIN TRY
		EXEC sp_ValidateSession;
	END TRY
	BEGIN CATCH
		DECLARE @SessionID INT = CAST(SESSION_CONTEXT(N'SessionID') AS INT);
		IF @SessionID IS NOT NULL
		BEGIN
			EXEC sp_LogoutAgent @SessionID;
		END;

		THROW
	END CATCH;

    SELECT sl.*
    FROM Sales sl
    JOIN AgentSession s ON sl.AgentID = s.AgentID
    WHERE s.SessionID = @SessionID;
END;

CREATE OR ALTER PROCEDURE sp_GetMyCommission
AS
BEGIN
    SET NOCOUNT ON;

	BEGIN TRY
		EXEC sp_ValidateSession;
	END TRY
	BEGIN CATCH
		DECLARE @SessionID INT = CAST(SESSION_CONTEXT(N'SessionID') AS INT);
		IF @SessionID IS NOT NULL
		BEGIN
			EXEC sp_LogoutAgent @SessionID;
		END;

		THROW
	END CATCH;

    SELECT c.*
    FROM Commission c
    JOIN AgentSession s ON c.AgentID = s.AgentID
    WHERE s.SessionID = @SessionID;
END;


CREATE OR ALTER PROCEDURE sp_GetMyLoginDetails
AS
BEGIN
    SET NOCOUNT ON;

	BEGIN TRY
		EXEC sp_ValidateSession;
	END TRY
	BEGIN CATCH
		DECLARE @SessionID INT = CAST(SESSION_CONTEXT(N'SessionID') AS INT);
		IF @SessionID IS NOT NULL
		BEGIN
			EXEC sp_LogoutAgent @SessionID;
		END;

		THROW
	END CATCH;

    SELECT u.Username, u.PasswordHash
    FROM User_Agent u
    JOIN AgentSession s ON u.AgentID = s.AgentID
    WHERE s.SessionID = @SessionID;
END;

------------------------------------------ PERMISSION MANAGEMENT --* --------------------------------------------------------
--REVOKE ALTER, CONTROL, REFERENCES, DELETE, INSERT, UPDATE, SELECT ON Sales FROM PUBLIC;
--Role: DB Admin 
GRANT CONTROL ON DATABASE::DAMS TO role_dba;

--table 10
GRANT SELECT, INSERT, UPDATE, DELETE ON Agents TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON AgentSession TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON Products TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON Sales TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON Commission TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON User_Agent TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON Employee TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON User_Employee TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON AuditLog TO role_dba;
GRANT SELECT, INSERT, UPDATE, DELETE ON EmployeeSession TO role_dba;

--view 12
GRANT SELECT ON v_Agents_Analytics TO role_dba;
GRANT SELECT ON v_Agents_Masked TO role_dba;
GRANT SELECT ON v_Commission_Analytics TO role_dba;
GRANT SELECT ON v_AgentStatus_Update TO role_dba;
GRANT SELECT ON v_AgentPII_Update TO role_dba;
GRANT SELECT ON v_ProductPrice_Update TO role_dba;
GRANT SELECT ON v_MyAgentProfile TO role_dba; -- can be deleted
GRANT SELECT ON v_MySales TO role_dba;
GRANT SELECT ON v_MyCommission TO role_dba;
GRANT SELECT ON v_MyLoginDetails TO role_dba;
GRANT SELECT ON v_MyEmployeeLoginDetails TO role_dba;
GRANT SELECT ON v_MyEmployeeProfile TO role_dba;

GRANT EXECUTE ON sp_AddAgentWithLogin TO role_dba;
GRANT EXECUTE ON sp_AddEmployeeWithLogin TO role_dba;
GRANT EXECUTE ON sp_AddProduct TO role_dba;
GRANT EXECUTE ON sp_AdminResetPassword TO role_dba;
GRANT EXECUTE ON sp_AdminResetPassword_Employee TO role_dba;
DENY EXECUTE ON sp_ChangePassword TO role_dba;
DENY EXECUTE ON sp_ChangeUsername TO role_dba;
GRANT EXECUTE ON sp_EmployeeChangePassword TO role_dba;
GRANT EXECUTE ON sp_EmployeeChangeUsername TO role_dba;
DENY EXECUTE ON sp_GetMyAgentProfile TO role_dba;
DENY EXECUTE ON sp_GetMyCommission TO role_dba;
DENY EXECUTE ON sp_GetMyLoginDetails TO role_dba;
DENY EXECUTE ON sp_GetMySales TO role_dba;
GRANT EXECUTE ON sp_InsertSale TO role_dba;
DENY EXECUTE ON sp_LoginAgent TO role_dba;
DENY EXECUTE ON sp_LogoutAgent TO role_dba;
GRANT EXECUTE ON sp_LoginEmployee TO role_dba;
GRANT EXECUTE ON sp_LogoutEmployee TO role_dba;

--DENY EXECUTE ON sp_LoginAgent TO role_dba;

--Role: Analytic
GRANT SELECT ON v_Agents_Analytics TO role_analytics;
GRANT SELECT ON v_Commission_Analytics TO role_analytics;
GRANT SELECT ON v_Agents_Masked TO role_analytics;

GRANT SELECT ON v_MyEmployeeLoginDetails TO role_analytics;
GRANT SELECT ON v_MyEmployeeProfile TO role_analytics;
GRANT EXECUTE ON sp_LoginEmployee TO role_analytics;
GRANT EXECUTE ON sp_LogoutEmployee TO role_analytics;
GRANT EXECUTE ON sp_EmployeeChangePassword TO role_analytics;
GRANT EXECUTE ON sp_EmployeeChangeUsername TO role_analytics;

DENY SELECT, INSERT, UPDATE, DELETE ON Agents TO role_analytics;
DENY SELECT, INSERT, UPDATE, DELETE ON Products TO role_analytics;
DENY SELECT, INSERT, UPDATE, DELETE ON Sales TO role_analytics;
DENY SELECT, INSERT, UPDATE, DELETE ON Commission TO role_analytics;
DENY SELECT, INSERT, UPDATE, DELETE ON User_Agent TO role_analytics;
DENY SELECT, INSERT, UPDATE, DELETE ON Employee TO role_analytics;
DENY SELECT, INSERT, UPDATE, DELETE ON User_Employee TO role_analytics;
DENY SELECT, INSERT, UPDATE, DELETE ON AuditLog TO role_analytics;

--Role: Marketing
GRANT SELECT ON v_Agents_Masked TO role_marketing;
GRANT SELECT ON Products TO role_marketing;

GRANT SELECT ON v_MyEmployeeLoginDetails TO role_marketing;
GRANT SELECT ON v_MyEmployeeProfile TO role_marketing;
GRANT EXECUTE ON sp_LoginEmployee TO role_marketing;
GRANT EXECUTE ON sp_LogoutEmployee TO role_marketing;
GRANT EXECUTE ON sp_EmployeeChangePassword TO role_marketing;
GRANT EXECUTE ON sp_EmployeeChangeUsername TO role_marketing;

DENY SELECT ON Agents TO role_marketing;
DENY SELECT ON Sales TO role_marketing;
DENY SELECT ON Commission TO role_marketing;
DENY SELECT ON User_Agent TO role_marketing;
DENY SELECT ON Employee TO role_marketing;
DENY SELECT ON User_Employee TO role_marketing;
DENY SELECT, INSERT, UPDATE, DELETE ON AuditLog TO role_marketing;


-- Role: Portal
GRANT EXECUTE ON sp_InsertSale TO role_portaldev;
GRANT SELECT ON Products TO role_portaldev;
GRANT SELECT ON Sales TO role_portaldev;

GRANT SELECT ON v_MyEmployeeLoginDetails TO role_portaldev;
GRANT SELECT ON v_MyEmployeeProfile TO role_portaldev;
GRANT EXECUTE ON sp_LoginEmployee TO role_portaldev;
GRANT EXECUTE ON sp_LogoutEmployee TO role_portaldev;
GRANT EXECUTE ON sp_EmployeeChangePassword TO role_portaldev;
GRANT EXECUTE ON sp_EmployeeChangeUsername TO role_portaldev;

DENY INSERT, UPDATE, DELETE ON Sales TO role_portaldev;
DENY SELECT, INSERT, UPDATE, DELETE ON Agents TO role_portaldev;
DENY SELECT, INSERT, UPDATE, DELETE ON Commission TO role_portaldev;
DENY SELECT, INSERT, UPDATE, DELETE ON User_Agent TO role_portaldev;
DENY SELECT, INSERT, UPDATE, DELETE ON Employee TO role_portaldev;
DENY SELECT, INSERT, UPDATE, DELETE ON User_Employee TO role_portaldev;
DENY SELECT, INSERT, UPDATE, DELETE ON AuditLog TO role_portaldev;


--Role: IT Admin
GRANT SELECT, UPDATE ON v_AgentStatus_Update TO role_it_admin;
GRANT SELECT, UPDATE ON v_AgentPII_Update TO role_it_admin;
GRANT SELECT ON v_Agents_Analytics TO role_it_admin;
GRANT SELECT ON v_Commission_Analytics TO role_it_admin;
GRANT EXECUTE ON sp_AddProduct TO role_it_admin;
GRANT SELECT ON Agents TO role_it_admin;
GRANT SELECT ON Products TO role_it_admin;

GRANT SELECT ON v_MyEmployeeLoginDetails TO role_it_admin;
GRANT SELECT ON v_MyEmployeeProfile TO role_it_admin;
GRANT EXECUTE ON sp_LoginEmployee TO role_it_admin;
GRANT EXECUTE ON sp_LogoutEmployee TO role_it_admin;
GRANT EXECUTE ON sp_EmployeeChangePassword TO role_it_admin;
GRANT EXECUTE ON sp_EmployeeChangeUsername TO role_it_admin;

DENY UPDATE, INSERT, DELETE ON Agents TO role_it_admin;
DENY SELECT, UPDATE, INSERT, DELETE ON Sales TO role_it_admin;
DENY SELECT, UPDATE, INSERT, DELETE ON Products TO role_it_admin;
DENY SELECT, UPDATE, INSERT, DELETE ON Commission TO role_it_admin;
DENY SELECT, UPDATE, INSERT, DELETE ON User_Agent TO role_it_admin;
DENY SELECT, UPDATE, INSERT, DELETE ON Employee TO role_it_admin;
DENY SELECT, UPDATE, INSERT, DELETE ON User_Employee TO role_it_admin;
DENY SELECT, INSERT, UPDATE, DELETE ON AuditLog TO role_it_admin;


--Role: Agent/User
GRANT EXECUTE ON sp_GetMyAgentProfile TO role_agent;
GRANT EXECUTE ON sp_GetMySales TO role_agent;
GRANT EXECUTE ON sp_GetMyCommission TO role_agent;
GRANT EXECUTE ON sp_GetMyLoginDetails TO role_agent;

GRANT EXECUTE ON sp_LoginAgent TO role_agent;
GRANT EXECUTE ON sp_LoginAgent TO user_agent;
GRANT EXECUTE ON sp_LogoutAgent TO role_agent;
GRANT EXECUTE ON sp_LogoutAgent TO user_agent;
GRANT EXECUTE ON sp_ChangePassword TO role_agent;
GRANT EXECUTE ON sp_ChangeUsername TO role_agent;

DENY SELECT ON Agents TO role_agent;
DENY SELECT ON Sales TO role_agent;
DENY SELECT ON Commission TO role_agent; 
DENY SELECT ON User_Agent TO role_agent;
DENY SELECT ON Employee TO role_agent;
DENY SELECT ON User_Employee TO role_agent;
DENY SELECT, INSERT, UPDATE, DELETE ON AuditLog TO role_agent;

----------------------------------------- RLS (For User(Agent)) ---------------------------------------------------
--[Agent]
-- Login (updated with session handling)
CREATE OR ALTER PROCEDURE sp_LoginAgent
    @Username NVARCHAR(100),
    @Password NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    -- Allow RLS access to User_Agent for login
    EXEC sp_set_session_context @key = N'IsLoginProcess', @value = 1;

    DECLARE @Hash NVARCHAR(64) = CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CONVERT(VARCHAR(100), @Password)), 2);
    DECLARE @AgentID INT;

    SELECT @AgentID = AgentID
    FROM User_Agent
    WHERE Username = @Username AND PasswordHash = @Hash;

    IF @AgentID IS NOT NULL
    BEGIN
        DECLARE @SessionID INT;
        INSERT INTO AgentSession (AgentID) VALUES (@AgentID);
        SET @SessionID = SCOPE_IDENTITY();

        EXEC sp_set_session_context @key = N'AgentID', @value = @AgentID;
        EXEC sp_set_session_context @key = N'SessionID', @value = @SessionID;
        EXEC sp_set_session_context @key = N'IsLoggedIn', @value = 1;
        EXEC sp_set_session_context @key = N'Username', @value = @Username;

        -- Reset login process flag
        EXEC sp_set_session_context @key = N'IsLoginProcess', @value = 0;

        PRINT 'Logged in successfully';
        PRINT 'Welcome, ' + @Username;
    END
    ELSE
    BEGIN
        PRINT 'No matching AgentID found for username=' + @Username + ' with hash=' + @Hash;
        -- Reset login process flag on failure too
        EXEC sp_set_session_context @key = N'IsLoginProcess', @value = 0;
        THROW 50001, 'Invalid username or password', 1;
    END
END;

CREATE OR ALTER FUNCTION dbo.fn_AgentRLS(@AgentID INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS fn_securitypredicate_result
    WHERE 
        CAST(SESSION_CONTEXT(N'IsLoginProcess') AS INT) = 1
        OR CAST(SESSION_CONTEXT(N'IsLoggedIn') AS INT) = 1
        OR @AgentID = CAST(SESSION_CONTEXT(N'AgentID') AS INT);

CREATE SECURITY POLICY AgentFilter_Policy
ADD FILTER PREDICATE dbo.fn_AgentRLS(AgentID) ON dbo.Agents,
ADD FILTER PREDICATE dbo.fn_AgentRLS(AgentID) ON dbo.Sales,
ADD FILTER PREDICATE dbo.fn_AgentRLS(AgentID) ON dbo.Commission
WITH (STATE = ON);

----------------------------------------- RLS (For Employee)  ---------------------------------------------------
--[Employeee]: Login (latest with session handling)
CREATE OR ALTER PROCEDURE sp_LoginEmployee
    @Username NVARCHAR(50),
    @Password NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    -- Begin login process
    EXEC sp_set_session_context 'IsLoginProcess', 1;

    DECLARE 
        @StoredHash NVARCHAR(128),
        @Salt NVARCHAR(50),
        @ComputedHash NVARCHAR(128),
        @EmployeeID INT,
        @AssignedRole NVARCHAR(50),
        @CallerRole NVARCHAR(50);

    -- Retrieve user info (RLS access allowed because IsLoginProcess = 1)
    SELECT 
        @Salt = PasswordSalt, 
        @StoredHash = PasswordHash,
        @EmployeeID = EmployeeID,
        @AssignedRole = Role
    FROM User_Employee
    WHERE Username = @Username AND IsLocked = 0;

    -- Reset login process context
    EXEC sp_set_session_context 'IsLoginProcess', NULL;

    -- Validate username and not locked
    IF @Salt IS NULL
    BEGIN
        THROW 50001, 'Invalid username or account locked', 1;
    END

    -- Compute password hash
    SET @ComputedHash = CONVERT(NVARCHAR(128), HASHBYTES('SHA2_512', CONVERT(VARCHAR(100), @Password + @Salt)), 2);

    IF @ComputedHash <> @StoredHash
    BEGIN
        THROW 50002, 'Invalid password', 1;
    END

    -- Determine caller's current role via IS_ROLEMEMBER()
    -- Check against known roles you use in your system
    IF IS_ROLEMEMBER('role_dba') = 1
        SET @CallerRole = 'role_dba';
    ELSE IF IS_ROLEMEMBER('role_marketing') = 1
        SET @CallerRole = 'role_marketing';
    ELSE IF IS_ROLEMEMBER('role_it_admin') = 1
        SET @CallerRole = 'role_it_admin';
    ELSE IF IS_ROLEMEMBER('role_analytics') = 1
        SET @CallerRole = 'role_analytics';
	ELSE IF IS_ROLEMEMBER('role_portaldev') = 1
        SET @CallerRole = 'role_portaldev';
    ELSE
        SET @CallerRole = NULL;

    -- Enforce role match between SQL login and application-level role
    IF @CallerRole IS NULL OR @CallerRole <> @AssignedRole
    BEGIN
        THROW 50003, 'Access denied: role mismatch.', 1;
    END

    -- Insert session and set context
    DECLARE @NewSessionID INT;
    INSERT INTO EmployeeSession (EmployeeID)
    VALUES (@EmployeeID);

    SET @NewSessionID = SCOPE_IDENTITY();

    EXEC sp_set_session_context 'IsLoggedIn', 1;
    EXEC sp_set_session_context 'EmployeeID', @EmployeeID;
    EXEC sp_set_session_context 'Username', @Username;
    EXEC sp_set_session_context 'SessionID', @NewSessionID;
    EXEC sp_set_session_context 'Role', @AssignedRole;

    PRINT 'Login successful. Role authenticated. Session started.';
END


CREATE OR ALTER FUNCTION dbo.fn_EmployeeRLS(@EmployeeID INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS fn_securitypredicate_result
    WHERE 
        CAST(SESSION_CONTEXT(N'IsLoginProcess') AS INT) = 1
        OR CAST(SESSION_CONTEXT(N'IsLoggedIn') AS INT) = 1
        OR (
			IS_ROLEMEMBER('role_analytics') = 1
            OR IS_ROLEMEMBER('role_marketing') = 1
            OR IS_ROLEMEMBER('role_it_admin') = 1
			OR IS_ROLEMEMBER('role_portaldev') = 1
        )
        OR @EmployeeID = CAST(SESSION_CONTEXT(N'EmployeeID') AS INT);

CREATE SECURITY POLICY EmployeeFilter_Policy
ADD FILTER PREDICATE dbo.fn_EmployeeRLS(EmployeeID) ON dbo.Employee,
ADD FILTER PREDICATE dbo.fn_EmployeeRLS(EmployeeID) ON dbo.User_Employee
WITH (STATE = ON);

SELECT * FROM Employee
SELECT * FROM User_Employee

---------------------------------------- ADDITIONAL FEATURE ---------------------------------------------------
-- Session Handling (Session Expiry) -- DONE Implemented (wait to check whether session timeout will logout etc)
----------------------------------------- (For User(Agent)) ---------------------------------------------------
--Create new agent session tracking table
CREATE TABLE AgentSession (
    SessionID INT IDENTITY(1,1) PRIMARY KEY,
    AgentID INT NOT NULL,
    LoginTime DATETIME NOT NULL DEFAULT GETDATE(),
    LastActivity DATETIME NOT NULL DEFAULT GETDATE(),
    IsActive BIT NOT NULL DEFAULT 1
);

-- function to check session 
CREATE OR ALTER PROCEDURE sp_ValidateSession
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @SessionID INT = CAST(SESSION_CONTEXT(N'SessionID') AS INT);

    IF @SessionID IS NULL
    BEGIN
        THROW 50003, 'SessionID not found in session context.', 1;
    END

    IF NOT EXISTS (
        SELECT 1 FROM AgentSession
        WHERE SessionID = @SessionID
          AND IsActive = 1
          AND DATEADD(MINUTE, 30, LastActivity) > GETDATE()
    )
    BEGIN

        UPDATE AgentSession
        SET IsActive = 0
        WHERE SessionID = @SessionID;

        THROW 50002, 'Session expired. Please login again.', 1;
    END
    ELSE
    BEGIN
        UPDATE AgentSession
        SET LastActivity = GETDATE()
        WHERE SessionID = @SessionID;
    END
END;

-- Agent logout
CREATE OR ALTER PROCEDURE sp_LogoutAgent
    @SessionID INT = NULL
AS
BEGIN
    SET NOCOUNT ON;

    IF @SessionID IS NULL
    BEGIN
        SET @SessionID = CAST(SESSION_CONTEXT(N'SessionID') AS INT);
    END

    IF @SessionID IS NULL
    BEGIN
        THROW 50001, 'SessionID not found in context or parameters', 1;
    END

    UPDATE AgentSession
    SET IsActive = 0, LastActivity = GETDATE()
    WHERE SessionID = @SessionID;
    
    PRINT 'Logged out successfully';
END;

----------------------------------------- (For Employee)) ---------------------------------------------------
CREATE TABLE EmployeeSession (
    SessionID INT IDENTITY(1,1) PRIMARY KEY,
    EmployeeID INT NOT NULL,
    LoginTime DATETIME NOT NULL DEFAULT GETDATE(),
    LastActivity DATETIME NOT NULL DEFAULT GETDATE(),
    LogoutTime DATETIME NULL,
    IsActive BIT NOT NULL DEFAULT 1,
    FOREIGN KEY (EmployeeID) REFERENCES Employee(EmployeeID)
);

CREATE OR ALTER PROCEDURE sp_validateEmployeeSession
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @SessionID INT = TRY_CAST(SESSION_CONTEXT(N'SessionID') AS INT);
    DECLARE @EmployeeID INT = TRY_CAST(SESSION_CONTEXT(N'EmployeeID') AS INT);
    DECLARE @IsActive BIT;
    DECLARE @CurrentTime DATETIME = GETDATE();
    DECLARE @LogoutTime DATETIME;

    -- Check if session context variables exist
    IF @SessionID IS NULL OR @EmployeeID IS NULL
    BEGIN
        THROW 50010, 'Session not found or user not logged in. Please login first.', 1;
    END

    -- Retrieve IsActive and LogoutTime for the session
    SELECT 
        @IsActive = IsActive,
        @LogoutTime = LogoutTime
    FROM EmployeeSession
    WHERE SessionID = @SessionID AND EmployeeID = @EmployeeID;

    -- Check if session exists and is active
    IF @IsActive IS NULL OR @IsActive = 0
    BEGIN
        THROW 50011, 'Session is inactive or invalid. Please login again.', 1;
    END

    -- Check if session has expired based on LogoutTime
    IF @LogoutTime IS NOT NULL AND @CurrentTime > @LogoutTime
    BEGIN
        -- Mark session as inactive due to expiry
        UPDATE EmployeeSession
        SET IsActive = 0
        WHERE SessionID = @SessionID;

        THROW 50012, 'Session expired. Please login again.', 1;
    END

    -- Update LastActivity timestamp and extend LogoutTime by 30 minutes (sliding expiration)
    UPDATE EmployeeSession
    SET LastActivity = @CurrentTime,
        LogoutTime = DATEADD(MINUTE, 30, @CurrentTime)
    WHERE SessionID = @SessionID;
END;

--logout
CREATE OR ALTER PROCEDURE sp_LogoutEmployee
    @SessionID INT = NULL
AS
BEGIN
    SET NOCOUNT ON;

    IF @SessionID IS NULL
    BEGIN
        SET @SessionID = TRY_CAST(SESSION_CONTEXT(N'SessionID') AS INT);
    END

    IF @SessionID IS NULL
    BEGIN
        THROW 50002, 'SessionID not found for employee (not provided and not in session context)', 1;
    END

    UPDATE EmployeeSession
    SET IsActive = 0, LastActivity = GETDATE()
    WHERE SessionID = @SessionID;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details, ActionTime)
    VALUES (
        'EmployeeSession',
        'LOGOUT',
        CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
        CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT('Employee SessionID ', @SessionID, ' logged out.'),
        GETDATE()
    );

    EXEC sp_set_session_context 'IsLoggedIn', NULL;
    EXEC sp_set_session_context 'EmployeeID', NULL;
    EXEC sp_set_session_context 'Username', NULL;
    EXEC sp_set_session_context 'Role', NULL;
    EXEC sp_set_session_context 'SessionID', NULL;
    EXEC sp_set_session_context 'AgentID', NULL;

    PRINT 'Employee logged out successfully';
END;

----------------------------------------- (For Employee)) ---------------------------------------------------
CREATE OR ALTER FUNCTION dbo.fn_MustLoginRLS()
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS fn_result
    WHERE 
	CAST(SESSION_CONTEXT(N'IsLoggedIn') AS INT) = 1
	OR CAST(SESSION_CONTEXT(N'IsLoginProcess') AS INT) = 1;

CREATE SECURITY POLICY MustLogin_Policy
ADD FILTER PREDICATE dbo.fn_MustLoginRLS() ON dbo.AgentSession,
ADD FILTER PREDICATE dbo.fn_MustLoginRLS() ON dbo.AuditLog,
ADD FILTER PREDICATE dbo.fn_MustLoginRLS() ON dbo.Products,
ADD FILTER PREDICATE dbo.fn_MustLoginRLS() ON dbo.User_Agent
WITH (STATE = ON);

SELECT * FROM AgentSession
SELECT * FROM AuditLog
SELECT * FROM Products
SELECT * FROM User_Agent

------------------------------------------------------------- AUDITING  ---------------------------------------------------------
SELECT SERVERPROPERTY('MachineName') AS Server_Machine,
       SERVERPROPERTY('InstanceName') AS Instance_Name;

USE master
-- 1. Specifically to capture login and logouts
CREATE SERVER AUDIT Audit_DAMS
TO FILE (
    FILEPATH = 'Path_to_sqlauditfolder',
    MAX_ROLLOVER_FILES = 10
)
WITH (
    QUEUE_DELAY = 1000,
    ON_FAILURE = CONTINUE
);

ALTER SERVER AUDIT Audit_DAMS WITH (STATE = ON);

-- 2. Create Database Audit Specification to audit specific actions
USE master;

SELECT name, audit_name, is_state_enabled
FROM sys.database_audit_specifications
WHERE audit_name = 'Audit_DAMS';

-- for server-level events (login/logout, server DDL, DCL)
CREATE SERVER AUDIT SPECIFICATION AuditSpec_Server_DAMS
FOR SERVER AUDIT Audit_DAMS
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (FAILED_LOGIN_GROUP),
    ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),  -- Server role changes
    ADD (SERVER_OBJECT_CHANGE_GROUP),       -- Server-level DDL changes
    ADD (SERVER_PERMISSION_CHANGE_GROUP)    -- Server-level DCL changes
WITH (STATE = ON);

USE DAMS;

CREATE DATABASE AUDIT SPECIFICATION AuditSpec_DB_DAMS
FOR SERVER AUDIT Audit_DAMS
	-- USER_TABLES: Audit INSERT, UPDATE, DELETE
	ADD (INSERT ON dbo.Agents BY [public]),
	ADD (UPDATE ON dbo.Agents BY [public]),
	ADD (DELETE ON dbo.Agents BY [public]),

	ADD (INSERT ON dbo.Commission BY [public]),
	ADD (UPDATE ON dbo.Commission BY [public]),
	ADD (DELETE ON dbo.Commission BY [public]),

	ADD (INSERT ON dbo.Products BY [public]),
	ADD (UPDATE ON dbo.Products BY [public]),
	ADD (DELETE ON dbo.Products BY [public]),

	ADD (INSERT ON dbo.Sales BY [public]),
	ADD (UPDATE ON dbo.Sales BY [public]),
	ADD (DELETE ON dbo.Sales BY [public]),

	ADD (INSERT ON dbo.User_Agent BY [public]),
	ADD (UPDATE ON dbo.User_Agent BY [public]),
	ADD (DELETE ON dbo.User_Agent BY [public]),

	ADD (INSERT ON dbo.Employee BY [public]),
	ADD (UPDATE ON dbo.Employee BY [public]),
	ADD (DELETE ON dbo.Employee BY [public]),

	ADD (INSERT ON dbo.EmployeeSession BY [public]),
	ADD (UPDATE ON dbo.EmployeeSession BY [public]),
	ADD (DELETE ON dbo.EmployeeSession BY [public]),

	ADD (INSERT ON dbo.User_Employee BY [public]),
	ADD (UPDATE ON dbo.User_Employee BY [public]),
	ADD (DELETE ON dbo.User_Employee BY [public]),

	ADD (INSERT ON dbo.AgentSession BY [public]),
	ADD (UPDATE ON dbo.AgentSession BY [public]),
	ADD (DELETE ON dbo.AgentSession BY [public]),

	ADD (INSERT ON dbo.AuditLog BY [public]),
	ADD (UPDATE ON dbo.AuditLog BY [public]),
	ADD (DELETE ON dbo.AuditLog BY [public]),

	-- VIEWS & INLINE TABLE-VALUED FUNCTIONS: Audit SELECT only
	ADD (SELECT ON dbo.v_AgentPII_Update BY [public]),
	ADD (SELECT ON dbo.v_Agents_Analytics BY [public]),
	ADD (SELECT ON dbo.v_Agents_Masked BY [public]),
	ADD (SELECT ON dbo.v_AgentStatus_Update BY [public]),
	ADD (SELECT ON dbo.v_Commission_Analytics BY [public]),
	ADD (SELECT ON dbo.v_ProductPrice_Update BY [public]),

	ADD (EXECUTE ON dbo.sp_GetMyAgentProfile BY [public]),
	ADD (EXECUTE ON dbo.sp_GetMySales BY [public]),
	ADD (EXECUTE ON dbo.sp_GetMyCommission BY [public]),
	ADD (EXECUTE ON dbo.sp_GetMyLoginDetails BY [public]),

	-- STORED PROCEDURES: Audit EXECUTE
	ADD (EXECUTE ON dbo.sp_AddAgentWithLogin BY [public]),
	ADD (EXECUTE ON dbo.sp_AddProduct BY [public]),
	ADD (EXECUTE ON dbo.sp_AdminResetPassword BY [public]),
	ADD (EXECUTE ON dbo.sp_ChangePassword BY [public]),
	ADD (EXECUTE ON dbo.sp_ChangeUsername BY [public]),
	ADD (EXECUTE ON dbo.sp_InsertSale BY [public]),
	ADD (EXECUTE ON dbo.sp_LoginAgent BY [public]),
	ADD (EXECUTE ON dbo.sp_LogoutAgent BY [public]),
	ADD (EXECUTE ON dbo.sp_AddEmployeeWithLogin BY [public]),
	ADD (EXECUTE ON dbo.sp_AdminResetPassword_Employee BY [public]),
	ADD (EXECUTE ON dbo.sp_EmployeeChangePassword BY [public]),
	ADD (EXECUTE ON dbo.sp_EmployeeChangeUsername BY [public]),
	ADD (EXECUTE ON dbo.sp_LoginEmployee BY [public]),
	ADD (EXECUTE ON dbo.sp_LogoutEmployee BY [public]),
	ADD (EXECUTE ON dbo.sp_validateEmployeeSession BY [public]),
	ADD (EXECUTE ON dbo.sp_ValidateSession BY [public]),
	ADD (SELECT ON dbo.v_MyAgentProfile BY [public]),
	ADD (SELECT ON dbo.v_MyCommission BY [public]),
	ADD (SELECT ON dbo.v_MyEmployeeLoginDetails BY [public]),
	ADD (SELECT ON dbo.v_MyEmployeeProfile BY [public]),
	ADD (SELECT ON dbo.v_MyLoginDetails BY [public]),
	ADD (SELECT ON dbo.v_MySales BY [public]),

    ADD (DATABASE_OBJECT_CHANGE_GROUP),
    ADD (DATABASE_PERMISSION_CHANGE_GROUP),
	ADD (SCHEMA_OBJECT_CHANGE_GROUP),
	ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP),
	ADD (DATABASE_PERMISSION_CHANGE_GROUP),
	ADD (DATABASE_PRINCIPAL_CHANGE_GROUP)
WITH (STATE = ON);

-- Audit Testing-----------------------------------------
-- Check SQL Server Audit use this query
SELECT
    event_time,
    server_principal_name,
    session_id,
    database_name,
    statement,
    action_id
FROM sys.fn_get_audit_file ('Path_to_sqlaudit.sqlaudit', DEFAULT, DEFAULT)
WHERE server_principal_name LIKE 'login_%' and action_id LIKE 'LGIF' ;

SELECT
    event_time,
    server_principal_name,
    database_name,
    object_name,
    statement,
    action_id,
    succeeded,
    session_id,
    server_instance_name
FROM sys.fn_get_audit_file ('Path_to_sqlaudit.sqlaudit', DEFAULT, DEFAULT)
WHERE server_principal_name LIKE 'login_%'
ORDER BY event_time DESC;

SELECT 
    event_time,
    action_id,
    statement,
    database_name,
    object_name,
    server_principal_name,
    session_id,
    client_ip,
    application_name
FROM sys.fn_get_audit_file('Path_to_sqlaudit.sqlaudit', DEFAULT, DEFAULT)
WHERE action_id IN ('SL', 'IN', 'UP', 'DL'); 

SELECT * FROM sys.server_audit_specifications;
SELECT * FROM sys.database_audit_specifications;

IF EXISTS (
    SELECT * FROM sys.database_audit_specifications
    WHERE name = 'AuditSpec_DB_DAMS'
)
BEGIN
    ALTER DATABASE AUDIT SPECIFICATION AuditSpec_DB_DAMS
    WITH (STATE = OFF);
    
    DROP DATABASE AUDIT SPECIFICATION AuditSpec_DB_DAMS;
END


-- AuditLog --*
CREATE TABLE AuditLog (
    AuditID INT IDENTITY(1,1) PRIMARY KEY,
    TableName NVARCHAR(128),
    ActionType NVARCHAR(20), -- INSERT, UPDATE, DELETE, LOGIN, LOGOUT, etc.
    UserName NVARCHAR(100),
    UserRole NVARCHAR(50),
    ActionTime DATETIME DEFAULT GETDATE(),
    ClientIP NVARCHAR(50) NULL, -- Optional: track IP from app
    Details NVARCHAR(MAX) -- JSON or descriptive info about action
);

-- DML Auditing for each table *8 (Old/New Data)
-- Agents table audit trigger
CREATE OR ALTER TRIGGER trg_Agents_Audit
ON dbo.Agents
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'Agents',
        @Action,
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT(
            'OldData: ', (SELECT * FROM deleted FOR JSON PATH),
            '; NewData: ', (SELECT * FROM inserted FOR JSON PATH)
        );
END;


-- Products table audit trigger
CREATE OR ALTER TRIGGER trg_Products_Audit
ON dbo.Products
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'Products',
        @Action,
        CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),

        CONCAT(
            'OldData: ', (SELECT * FROM deleted FOR JSON PATH),
            '; NewData: ', (SELECT * FROM inserted FOR JSON PATH)
        );
END;


-- Sales table audit trigger
CREATE OR ALTER TRIGGER trg_Sales_Audit
ON dbo.Sales
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'Sales',
        @Action,
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT(
            'OldData: ', (SELECT * FROM deleted FOR JSON PATH),
            '; NewData: ', (SELECT * FROM inserted FOR JSON PATH)
        );
END;


-- Commission table audit trigger
CREATE OR ALTER TRIGGER trg_Commission_Audit
ON dbo.Commission
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'Commission',
        @Action,
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT(
            'OldData: ', (SELECT * FROM deleted FOR JSON PATH),
            '; NewData: ', (SELECT * FROM inserted FOR JSON PATH)
        );
END;

-- User_Agent table audit trigger
CREATE OR ALTER TRIGGER trg_User_Agent_Audit
ON dbo.User_Agent
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'User_Agent',
        @Action,
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT(
            'OldData: ', (SELECT * FROM deleted FOR JSON PATH),
            '; NewData: ', (SELECT * FROM inserted FOR JSON PATH)
        );
END;

-- Employee table audit trigger
CREATE OR ALTER TRIGGER trg_Employee_Audit
ON dbo.Employee
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'Employee',
        @Action,
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT(
            'OldData: ', (SELECT * FROM deleted FOR JSON PATH),
            '; NewData: ', (SELECT * FROM inserted FOR JSON PATH)
        );
END;

-- User_Employee table audit trigger
CREATE OR ALTER TRIGGER trg_User_Employee_Audit
ON dbo.User_Employee
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'User_Employee',
        @Action,
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
		CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT(
            'OldData: ', (SELECT * FROM deleted FOR JSON PATH),
            '; NewData: ', (SELECT * FROM inserted FOR JSON PATH)
        );
END;

CREATE OR ALTER TRIGGER trg_AgentSession_Audit
ON dbo.AgentSession
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'AgentSession',
        @Action,
        CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
        CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT(
            'OldData: ', ISNULL((SELECT * FROM deleted FOR JSON PATH), 'null'),
            '; NewData: ', ISNULL((SELECT * FROM inserted FOR JSON PATH), 'null')
        );
END;

CREATE OR ALTER TRIGGER trg_EmployeeSession_Audit
ON dbo.EmployeeSession
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
    DECLARE @Action NVARCHAR(20) =
        CASE 
            WHEN EXISTS(SELECT * FROM inserted) AND EXISTS(SELECT * FROM deleted) THEN 'UPDATE'
            WHEN EXISTS(SELECT * FROM inserted) THEN 'INSERT'
            ELSE 'DELETE'
        END;

    INSERT INTO AuditLog (TableName, ActionType, UserName, UserRole, Details)
    SELECT
        'EmployeeSession',
        @Action,
        CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Username')),
        CONVERT(NVARCHAR(100), SESSION_CONTEXT(N'Role')),
        CONCAT(
            'OldData: ', ISNULL((SELECT * FROM deleted FOR JSON PATH), 'null'),
            '; NewData: ', ISNULL((SELECT * FROM inserted FOR JSON PATH), 'null')
        );
END;

-- Prevent Audit Table Tampering
CREATE TRIGGER trg_PreventAuditUpdate
ON dbo.AuditLog
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    RAISERROR ('Audit logs cannot be modified or deleted.', 16, 1);
    ROLLBACK TRANSACTION;
END;

-----------------------------------------------ENCRYPTION ---------------------------------------------------
USE master;

CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'REDACTED_Key';

CREATE CERTIFICATE DAMS_Cert
WITH SUBJECT = 'Certificate for DAMS TDE';

USE DAMS;

CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE DAMS_Cert;

ALTER DATABASE DAMS
SET ENCRYPTION ON;

-- To Verify TDE is Enabled
SELECT 
    db.name AS DatabaseName,
    dek.encryption_state,
    dek.encryptor_type,
    dek.key_algorithm,
    dek.key_length
FROM sys.databases db
JOIN sys.dm_database_encryption_keys dek
    ON db.database_id = dek.database_id;
--encryption_state = 3 means encryption is active.
--encryptor_type = CERTIFICATE confirms it's using your certificate.

-- Backup certificate
BACKUP CERTIFICATE DAMS_Cert
TO FILE = 'Path_to_Cert.cer'
WITH PRIVATE KEY (
    FILE = 'Path_to_Cert_PrivateKey.pvk',
    ENCRYPTION BY PASSWORD = 'REDACTED_Key'
);

-- Backup master key
BACKUP MASTER KEY
TO FILE = 'Path_to_Cert.cer'
ENCRYPTION BY PASSWORD = 'REDACTED_key';


-- IF wanted to disable TDE
ALTER DATABASE DAMS SET ENCRYPTION OFF;

DROP DATABASE ENCRYPTION KEY;
