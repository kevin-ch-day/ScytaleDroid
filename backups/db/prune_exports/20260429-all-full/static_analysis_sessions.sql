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
-- Table structure for table `static_analysis_sessions`
--

DROP TABLE IF EXISTS `static_analysis_sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `static_analysis_sessions` (
  `static_session_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `session_stamp` varchar(128) NOT NULL,
  `scope_label` varchar(191) NOT NULL DEFAULT '',
  `session_label` varchar(191) DEFAULT NULL,
  `session_status` varchar(32) NOT NULL DEFAULT 'UNKNOWN',
  `session_disposition` varchar(64) NOT NULL DEFAULT 'unknown_needs_review',
  `disposition_confidence` varchar(16) NOT NULL DEFAULT 'medium',
  `total_run_count` int(10) unsigned NOT NULL DEFAULT 0,
  `completed_run_count` int(10) unsigned NOT NULL DEFAULT 0,
  `failed_run_count` int(10) unsigned NOT NULL DEFAULT 0,
  `interrupted_run_count` int(10) unsigned NOT NULL DEFAULT 0,
  `persist_error_run_count` int(10) unsigned NOT NULL DEFAULT 0,
  `missing_artifacts_run_count` int(10) unsigned NOT NULL DEFAULT 0,
  `total_findings_rows` bigint(20) unsigned NOT NULL DEFAULT 0,
  `total_permission_matrix_rows` bigint(20) unsigned NOT NULL DEFAULT 0,
  `total_permission_risk_rows` bigint(20) unsigned NOT NULL DEFAULT 0,
  `total_string_summary_rows` bigint(20) unsigned NOT NULL DEFAULT 0,
  `total_string_sample_rows` bigint(20) unsigned NOT NULL DEFAULT 0,
  `session_link_rows` bigint(20) unsigned NOT NULL DEFAULT 0,
  `rollup_rows` bigint(20) unsigned NOT NULL DEFAULT 0,
  `persistence_failure_rows` bigint(20) unsigned NOT NULL DEFAULT 0,
  `web_visibility_default` varchar(16) NOT NULL DEFAULT 'operator',
  `cleanup_status` varchar(32) NOT NULL DEFAULT 'none',
  `superseded_by_session_id` bigint(20) unsigned DEFAULT NULL,
  `tool_semver` varchar(32) DEFAULT NULL,
  `tool_git_commit` varchar(40) DEFAULT NULL,
  `schema_version` varchar(32) DEFAULT NULL,
  `first_created_at` datetime DEFAULT NULL,
  `last_ended_at` datetime DEFAULT NULL,
  `refreshed_at_utc` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at_utc` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`static_session_id`),
  UNIQUE KEY `ux_static_session_natural` (`session_stamp`,`scope_label`),
  KEY `ix_static_session_disposition` (`session_disposition`,`web_visibility_default`),
  KEY `ix_static_session_cleanup` (`cleanup_status`),
  KEY `ix_static_session_stamp` (`session_stamp`),
  KEY `fk_static_session_superseded` (`superseded_by_session_id`),
  CONSTRAINT `fk_static_session_superseded` FOREIGN KEY (`superseded_by_session_id`) REFERENCES `static_analysis_sessions` (`static_session_id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `static_analysis_sessions`
--
-- WHERE:  session_stamp='20260429-all-full'

LOCK TABLES `static_analysis_sessions` WRITE;
/*!40000 ALTER TABLE `static_analysis_sessions` DISABLE KEYS */;
INSERT INTO `static_analysis_sessions` VALUES
(2,'20260429-all-full','All harvested apps','20260429-all-full','FAILED','broken_persist_error_session','high',120,0,120,0,119,1,1,0,0,1,0,0,0,0,'hidden','export_pending',NULL,'2.2.1','9dff1d227367','0.2.6','2026-04-29 20:52:47','2026-04-30 02:56:24','2026-05-11 17:29:45','2026-05-11 17:28:31');
/*!40000 ALTER TABLE `static_analysis_sessions` ENABLE KEYS */;
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
