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
-- Table structure for table `static_string_sample_sets`
--

DROP TABLE IF EXISTS `static_string_sample_sets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `static_string_sample_sets` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `summary_id` bigint(20) unsigned NOT NULL,
  `static_run_id` bigint(20) unsigned DEFAULT NULL,
  `selection_params` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`selection_params`)),
  `selection_version` varchar(32) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_sample_set_summary` (`summary_id`),
  KEY `ix_sample_set_static_run` (`static_run_id`)
) ENGINE=InnoDB AUTO_INCREMENT=2279 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `static_string_sample_sets`
--
-- WHERE:  summary_id IN (SELECT id FROM static_string_summary WHERE session_stamp='20260429-all-full')

LOCK TABLES `static_string_sample_sets` WRITE;
/*!40000 ALTER TABLE `static_string_sample_sets` DISABLE KEYS */;
INSERT INTO `static_string_sample_sets` VALUES
(1451,1451,1711,'{\"bucket_priorities\": {\"analytics_ids\": 80, \"api_keys\": 90, \"certs\": 40, \"cloud_refs\": 70, \"endpoints\": 100, \"flags\": 45, \"high_entropy\": 85, \"http_cleartext\": 95, \"ipc\": 60, \"uris\": 55}, \"max_samples\": 2, \"min_entropy\": 4.8, \"policy_root\": \"config/strings\", \"policy_version\": \"5bfc4b6efa2b27c8e36c4e8c0fe062d1a9c4af9195c63859777d0a1b31cd4d53\", \"selection_version\": \"v1\", \"sort_key\": \"confidence_desc,length_desc,hash_asc,src_asc\"}','v1','2026-04-30 02:56:24');
/*!40000 ALTER TABLE `static_string_sample_sets` ENABLE KEYS */;
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
