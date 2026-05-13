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
-- Table structure for table `static_analysis_findings`
--

DROP TABLE IF EXISTS `static_analysis_findings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `static_analysis_findings` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `run_id` bigint(20) unsigned NOT NULL,
  `finding_id` varchar(128) DEFAULT NULL,
  `status` varchar(32) DEFAULT NULL,
  `severity` varchar(32) DEFAULT NULL,
  `severity_raw` varchar(64) DEFAULT NULL,
  `category` varchar(64) DEFAULT NULL,
  `title` varchar(512) DEFAULT NULL,
  `tags` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`tags`)),
  `evidence` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`evidence`)),
  `fix` text DEFAULT NULL,
  `rule_id` varchar(128) DEFAULT NULL,
  `cvss_score` decimal(4,1) DEFAULT NULL,
  `masvs_control` varchar(32) DEFAULT NULL,
  `detector` varchar(64) DEFAULT NULL,
  `module` varchar(64) DEFAULT NULL,
  `evidence_refs` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`evidence_refs`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `masvs_area` varchar(32) DEFAULT NULL,
  `masvs_control_id` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_static_findings_run` (`run_id`),
  KEY `ix_static_findings_severity` (`run_id`,`severity`),
  KEY `ix_static_findings_rule` (`run_id`,`rule_id`),
  KEY `ix_static_findings_rule_severity` (`rule_id`,`severity`,`run_id`),
  KEY `ix_static_findings_run_detector` (`run_id`,`detector`)
) ENGINE=InnoDB AUTO_INCREMENT=72810 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `static_analysis_findings`
--
-- WHERE:  run_id IN (SELECT id FROM static_analysis_runs WHERE session_stamp='20260429-all-full')

LOCK TABLES `static_analysis_findings` WRITE;
/*!40000 ALTER TABLE `static_analysis_findings` DISABLE KEYS */;
INSERT INTO `static_analysis_findings` VALUES
(46674,1711,'risk_profile','INFO','Info',NULL,'OTHER','Composite risk — Informational','[]','{\"detail\": \"Composite static risk score 0 (Informational).\"}','Prioritise remediation of P0/P1 findings to reduce the score.',NULL,NULL,'OTHER','correlation_engine',NULL,NULL,'2026-04-30 02:56:24','OTHER',NULL);
/*!40000 ALTER TABLE `static_analysis_findings` ENABLE KEYS */;
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
