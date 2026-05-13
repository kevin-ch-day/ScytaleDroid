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
-- Table structure for table `static_string_summary`
--

DROP TABLE IF EXISTS `static_string_summary`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `static_string_summary` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `package_name` varchar(191) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `session_stamp` varchar(64) NOT NULL,
  `scope_label` varchar(191) NOT NULL,
  `endpoints` int(10) unsigned NOT NULL DEFAULT 0,
  `http_cleartext` int(10) unsigned NOT NULL DEFAULT 0,
  `api_keys` int(10) unsigned NOT NULL DEFAULT 0,
  `analytics_ids` int(10) unsigned NOT NULL DEFAULT 0,
  `cloud_refs` int(10) unsigned NOT NULL DEFAULT 0,
  `ipc` int(10) unsigned NOT NULL DEFAULT 0,
  `uris` int(10) unsigned NOT NULL DEFAULT 0,
  `flags` int(10) unsigned NOT NULL DEFAULT 0,
  `certs` int(10) unsigned NOT NULL DEFAULT 0,
  `high_entropy` int(10) unsigned NOT NULL DEFAULT 0,
  `placeholders_downgraded` int(10) unsigned NOT NULL DEFAULT 0,
  `placeholders_suppressed` int(10) unsigned NOT NULL DEFAULT 0,
  `doc_hosts_suppressed` int(10) unsigned NOT NULL DEFAULT 0,
  `doc_cdns_suppressed` int(10) unsigned NOT NULL DEFAULT 0,
  `trailing_punct_trimmed` int(10) unsigned NOT NULL DEFAULT 0,
  `ws_wss_seen` int(10) unsigned NOT NULL DEFAULT 0,
  `ipv6_seen` int(10) unsigned NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `static_run_id` bigint(20) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_string_summary` (`package_name`,`session_stamp`,`scope_label`),
  KEY `ix_string_summary_session` (`session_stamp`),
  KEY `ix_string_summary_static_run` (`static_run_id`,`scope_label`)
) ENGINE=InnoDB AUTO_INCREMENT=2279 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `static_string_summary`
--
-- WHERE:  session_stamp='20260429-all-full'

LOCK TABLES `static_string_summary` WRITE;
/*!40000 ALTER TABLE `static_string_summary` DISABLE KEYS */;
INSERT INTO `static_string_summary` VALUES
(1451,'android.autoinstalls.config.motorola.layout','20260429-all-full','All harvested apps',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'2026-04-30 02:56:24',1711);
/*!40000 ALTER TABLE `static_string_summary` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-05-11 13:01:00
