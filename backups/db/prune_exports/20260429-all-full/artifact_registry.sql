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

LOCK TABLES `artifact_registry` WRITE;
/*!40000 ALTER TABLE `artifact_registry` DISABLE KEYS */;
INSERT INTO `artifact_registry` VALUES
(15245,'1711','static','static_baseline_json','host',NULL,'/home/secadmin/Laughlin/GitHub/ScytaleDroid/data/static_analysis/baseline/android.autoinstalls.config.motorola.layout-full-all-20260430T025624Z.json','n/a','6eecf8b603c194e661b2aac59f5aab8f568e8177ca9501fa6211ea07739e64fa',8709,'2026-04-30 02:56:24',NULL,NULL,NULL),
(15246,'1711','static','static_dynamic_plan_json','host',NULL,'/home/secadmin/Laughlin/GitHub/ScytaleDroid/data/static_analysis/dynamic_plan/android.autoinstalls.config.motorola.layout-full-all-sr1711-20260430T025624Z.json','n/a','933e885750cf302782c72d38368ba9a3e973f83fa7217b98cd64ce5f7789c2f0',3054,'2026-04-30 02:56:24',NULL,NULL,NULL),
(15247,'1711','static','manifest_evidence','host',NULL,'/home/secadmin/Laughlin/GitHub/ScytaleDroid/evidence/static_runs/1711/manifest_evidence.json','n/a','f6957ed56f9b3b458f2331f9b96687522f2a01c3a0a1ef4a296706455f398c8e',604,'2026-04-30 02:56:24',NULL,NULL,NULL),
(15248,'1711','static','static_report','host',NULL,'/home/secadmin/Laughlin/GitHub/ScytaleDroid/data/static_analysis/reports/latest/3d9d76d4c535634f02360b110e23b1fca2c3fca5482df6d4a684c9ad2ce6f6c3.json','n/a','c8132d587652aef18426b3029e5ba1c5fbb414ab63d5e4de8a65438469e501e1',83126,'2026-04-30 02:56:24',NULL,NULL,NULL);
/*!40000 ALTER TABLE `artifact_registry` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-05-11 13:05:44
