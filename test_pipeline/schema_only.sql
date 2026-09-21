--
-- PostgreSQL database dump
--

\restrict 1xjxLh8uf3BrP7dZb0s7VjYfjNMNxV1W1CHpK6SaCyQfOWBGNs6Q05vUM75dK7G

-- Dumped from database version 18.4 (Debian 18.4-1+b2)
-- Dumped by pg_dump version 18.4 (Debian 18.4-1+b2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alerts; Type: TABLE; Schema: public; Owner: vigilance
--

CREATE TABLE public.alerts (
    id character varying NOT NULL,
    "timestamp" character varying,
    rule_id character varying,
    rule_level integer,
    description character varying,
    agent_name character varying,
    agent_ip character varying,
    severity character varying,
    raw_data json,
    created_at timestamp without time zone
);


ALTER TABLE public.alerts OWNER TO vigilance;

--
-- Name: classifications; Type: TABLE; Schema: public; Owner: vigilance
--

CREATE TABLE public.classifications (
    id integer NOT NULL,
    alert_id character varying,
    severity character varying,
    reasoning text,
    mitre_tactics text,
    recommended_actions text,
    classified_at timestamp without time zone,
    verdict character varying,
    confidence character varying
);


ALTER TABLE public.classifications OWNER TO vigilance;

--
-- Name: classifications_id_seq; Type: SEQUENCE; Schema: public; Owner: vigilance
--

CREATE SEQUENCE public.classifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.classifications_id_seq OWNER TO vigilance;

--
-- Name: classifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: vigilance
--

ALTER SEQUENCE public.classifications_id_seq OWNED BY public.classifications.id;


--
-- Name: reports; Type: TABLE; Schema: public; Owner: vigilance
--

CREATE TABLE public.reports (
    id integer NOT NULL,
    alert_id character varying,
    severity character varying,
    agent_name character varying,
    report_text text,
    created_at timestamp without time zone
);


ALTER TABLE public.reports OWNER TO vigilance;

--
-- Name: reports_id_seq; Type: SEQUENCE; Schema: public; Owner: vigilance
--

CREATE SEQUENCE public.reports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.reports_id_seq OWNER TO vigilance;

--
-- Name: reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: vigilance
--

ALTER SEQUENCE public.reports_id_seq OWNED BY public.reports.id;


--
-- Name: classifications id; Type: DEFAULT; Schema: public; Owner: vigilance
--

ALTER TABLE ONLY public.classifications ALTER COLUMN id SET DEFAULT nextval('public.classifications_id_seq'::regclass);


--
-- Name: reports id; Type: DEFAULT; Schema: public; Owner: vigilance
--

ALTER TABLE ONLY public.reports ALTER COLUMN id SET DEFAULT nextval('public.reports_id_seq'::regclass);


--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: vigilance
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- Name: classifications classifications_pkey; Type: CONSTRAINT; Schema: public; Owner: vigilance
--

ALTER TABLE ONLY public.classifications
    ADD CONSTRAINT classifications_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: vigilance
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

\unrestrict 1xjxLh8uf3BrP7dZb0s7VjYfjNMNxV1W1CHpK6SaCyQfOWBGNs6Q05vUM75dK7G

