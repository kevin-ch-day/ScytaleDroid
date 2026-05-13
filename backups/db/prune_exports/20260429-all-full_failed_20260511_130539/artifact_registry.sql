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
-- Table structure for table `artifact_registry`
--

DROP TABLE IF EXISTS `artifact_registry`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `artifact_registry` (
  `artifact_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `run_id` varchar(64) NOT NULL,
  `run_type` varchar(16) NOT NULL,
  `artifact_type` varchar(64) NOT NULL,
  `origin` varchar(16) NOT NULL,
  `device_path` text DEFAULT NULL,
  `host_path` text DEFAULT NULL,
  `pull_status` varchar(16) DEFAULT NULL,
  `sha256` char(64) DEFAULT NULL,
  `size_bytes` bigint(20) DEFAULT NULL,
  `created_at_utc` datetime DEFAULT NULL,
  `pulled_at_utc` datetime DEFAULT NULL,
  `status_reason` varchar(191) DEFAULT NULL,
  `meta_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`meta_json`)),
  PRIMARY KEY (`artifact_id`),
  KEY `ix_artifact_run` (`run_id`,`run_type`),
  KEY `ix_artifact_type` (`artifact_type`)
) ENGINE=InnoDB AUTO_INCREMENT=19939 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `artifact_registry`
--
-- WHERE:  run_type='static' AND run_id IN (SELECT CAST(id AS CHAR) FROM static_analysis_runs WHERE session_stamp='20260429-all-full')

