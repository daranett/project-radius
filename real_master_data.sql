--
-- PostgreSQL database dump
--

\restrict C6yqfSyjAOsmvqBqLR5B95Cx4ho8bnThox1CAXPEPlTztk8HZ3OZ3riaDUYpiQ0

-- Dumped from database version 15.14
-- Dumped by pg_dump version 15.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: admin_users; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Data for Name: billing_packages; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Data for Name: nas; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Data for Name: mikrotik_credentials; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Data for Name: radgroupcheck; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Data for Name: radgroupreply; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: admin_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('public.admin_users_id_seq', 1, false);


--
-- Name: billing_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('public.billing_packages_id_seq', 1, false);


--
-- Name: mikrotik_credentials_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('public.mikrotik_credentials_id_seq', 1, false);


--
-- Name: nas_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('public.nas_id_seq', 1, false);


--
-- Name: radgroupcheck_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('public.radgroupcheck_id_seq', 1, false);


--
-- Name: radgroupreply_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('public.radgroupreply_id_seq', 1, false);


--
-- PostgreSQL database dump complete
--

\unrestrict C6yqfSyjAOsmvqBqLR5B95Cx4ho8bnThox1CAXPEPlTztk8HZ3OZ3riaDUYpiQ0

