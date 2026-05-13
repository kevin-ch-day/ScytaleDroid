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
-- Table structure for table `static_session_disposition_history`
--

DROP TABLE IF EXISTS `static_session_disposition_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `static_session_disposition_history` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `static_session_id` bigint(20) unsigned NOT NULL,
  `from_disposition` varchar(64) DEFAULT NULL,
  `to_disposition` varchar(64) NOT NULL,
  `reason` varchar(512) DEFAULT NULL,
  `actor` varchar(128) NOT NULL DEFAULT 'manual_sql',
  `detail_json` longtext DEFAULT NULL,
  `created_at_utc` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `ix_sess_disp_hist_session` (`static_session_id`,`created_at_utc`),
  CONSTRAINT `fk_sess_disp_hist_session` FOREIGN KEY (`static_session_id`) REFERENCES `static_analysis_sessions` (`static_session_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `static_session_disposition_history`
--
-- WHERE:  static_session_id IN (SELECT static_session_id FROM static_analysis_sessions WHERE session_stamp='20260429-all-full')

