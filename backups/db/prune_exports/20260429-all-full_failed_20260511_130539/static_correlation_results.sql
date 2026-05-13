/*M!999999\- enable the sandbox mode */ 
-- MariaDB dump 10.19  Distrib 10.11.16-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: scytaledroid_core_prod
-- ------------------------------------------------------
-- Server version	10.11.16-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `static_correlation_results`
--

DROP TABLE IF EXISTS `static_correlation_results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `static_correlation_results` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `static_run_id` bigint(20) NOT NULL,
  `package_name` varchar(255) NOT NULL,
  `correlation_key` varchar(128) NOT NULL,
  `severity_band` enum('INFO','WARN','FAIL') NOT NULL,
  `score` int(11) NOT NULL,
  `rationale` mediumtext NOT NULL,
  `evidence_path` varchar(1024) DEFAULT NULL,
  `evidence_preview` mediumtext DEFAULT NULL,
  `created_at_utc` datetime NOT NULL DEFAULT current_timestamp(),
  `governance_version` varchar(32) DEFAULT NULL,
  `governance_sha256` char(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_static_corr` (`static_run_id`,`package_name`,`correlation_key`),
  KEY `ix_static_corr_run_pkg` (`static_run_id`,`package_name`),
  KEY `ix_static_corr_key` (`correlation_key`),
  KEY `ix_static_corr_sev` (`severity_band`),
  KEY `ix_corr_gov` (`governance_version`)
) ENGINE=InnoDB AUTO_INCREMENT=6480 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `static_correlation_results`
--
-- WHERE:  static_run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp='20260429-all-full')

