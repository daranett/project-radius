--
-- Complete Database Structure + Default Admin User
-- Ready for Production/Demo
--

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
-- Name: generate_invoice_number(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.generate_invoice_number() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.invoice_number IS NULL THEN
        NEW.invoice_number := 'INV-' || EXTRACT(YEAR FROM CURRENT_DATE) || '-' || 
                             LPAD(EXTRACT(MONTH FROM CURRENT_DATE)::text, 2, '0') || '-' ||
                             LPAD(NEW.id::text, 4, '0');
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: admin_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_users (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    password_hash character varying(255) NOT NULL,
    full_name character varying(100),
    role character varying(20) DEFAULT 'operator'::character varying,
    is_active boolean DEFAULT true,
    last_login timestamp without time zone,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: admin_users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.admin_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.admin_users_id_seq OWNED BY public.admin_users.id;


--
-- Name: billing_customers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_customers (
    id integer NOT NULL,
    user_id integer,
    full_name character varying(100) NOT NULL,
    email character varying(100),
    phone character varying(20),
    address text,
    package_id integer,
    registration_date date DEFAULT CURRENT_DATE,
    status character varying(20) DEFAULT 'active'::character varying,
    notes text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    deleted_at timestamp without time zone,
    install_date date,
    due_day smallint,
    lat numeric(9,6),
    lng numeric(9,6),
    technician_notes text,
    photo_path character varying(255),
    CONSTRAINT billing_customers_due_day_check CHECK (((due_day >= 1) AND (due_day <= 31)))
);


--
-- Name: billing_invoices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_invoices (
    id integer NOT NULL,
    invoice_number character varying(50) NOT NULL,
    customer_id integer NOT NULL,
    package_id integer NOT NULL,
    period_month integer NOT NULL,
    period_year integer NOT NULL,
    amount numeric(10,2) NOT NULL,
    due_date date NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying,
    notes text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    deleted_at timestamp without time zone
);


--
-- Name: billing_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_packages (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    price_monthly numeric(10,2) DEFAULT 0 NOT NULL,
    price_daily numeric(10,2) DEFAULT 0 NOT NULL,
    bandwidth_limit character varying(50),
    session_timeout integer DEFAULT 3600,
    idle_timeout integer DEFAULT 300,
    is_active boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    deleted_at timestamp without time zone
);


--
-- Name: billing_customer_summary; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.billing_customer_summary AS
 SELECT c.id,
    c.full_name,
    c.email,
    c.phone,
    c.status AS customer_status,
    p.name AS package_name,
    p.price_monthly,
    ( SELECT count(*) AS count
           FROM public.billing_invoices i
          WHERE ((i.customer_id = c.id) AND ((i.status)::text = 'pending'::text) AND (i.deleted_at IS NULL))) AS pending_invoices,
    ( SELECT count(*) AS count
           FROM public.billing_invoices i
          WHERE ((i.customer_id = c.id) AND ((i.status)::text = 'paid'::text) AND (i.deleted_at IS NULL))) AS paid_invoices,
    ( SELECT COALESCE(sum(i.amount), (0)::numeric) AS "coalesce"
           FROM public.billing_invoices i
          WHERE ((i.customer_id = c.id) AND ((i.status)::text = 'paid'::text) AND (i.deleted_at IS NULL))) AS total_paid
   FROM (public.billing_customers c
     LEFT JOIN public.billing_packages p ON ((c.package_id = p.id)))
  WHERE (c.deleted_at IS NULL);


--
-- Name: billing_customers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.billing_customers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: billing_customers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.billing_customers_id_seq OWNED BY public.billing_customers.id;


--
-- Name: billing_invoices_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.billing_invoices_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: billing_invoices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.billing_invoices_id_seq OWNED BY public.billing_invoices.id;


--
-- Name: billing_monthly_revenue; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.billing_monthly_revenue AS
 SELECT i.period_year,
    i.period_month,
    count(i.id) AS total_invoices,
    sum(i.amount) AS total_amount,
    sum(
        CASE
            WHEN ((i.status)::text = 'paid'::text) THEN i.amount
            ELSE (0)::numeric
        END) AS paid_amount,
    sum(
        CASE
            WHEN ((i.status)::text = 'pending'::text) THEN i.amount
            ELSE (0)::numeric
        END) AS pending_amount
   FROM public.billing_invoices i
  WHERE (i.deleted_at IS NULL)
  GROUP BY i.period_year, i.period_month
  ORDER BY i.period_year DESC, i.period_month DESC;


--
-- Name: billing_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.billing_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: billing_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.billing_packages_id_seq OWNED BY public.billing_packages.id;


--
-- Name: billing_payments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.billing_payments (
    id integer NOT NULL,
    invoice_id integer NOT NULL,
    payment_method character varying(50) NOT NULL,
    amount numeric(10,2) NOT NULL,
    payment_date timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    reference_number character varying(100),
    notes text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    deleted_at timestamp without time zone
);


--
-- Name: billing_payments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.billing_payments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: billing_payments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.billing_payments_id_seq OWNED BY public.billing_payments.id;


--
-- Name: mikrotik_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mikrotik_credentials (
    id integer NOT NULL,
    nas_id integer NOT NULL,
    username character varying(100) NOT NULL,
    password character varying(255) NOT NULL,
    port integer DEFAULT 8728,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: mikrotik_credentials_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mikrotik_credentials_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mikrotik_credentials_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mikrotik_credentials_id_seq OWNED BY public.mikrotik_credentials.id;


--
-- Name: nas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nas (
    id integer NOT NULL,
    nasname text NOT NULL,
    shortname text NOT NULL,
    type text DEFAULT 'other'::text NOT NULL,
    ports integer,
    secret text NOT NULL,
    server text,
    community text,
    description text,
    require_ma text DEFAULT 'auto'::text NOT NULL,
    limit_proxy_state text DEFAULT 'auto'::text NOT NULL
);


--
-- Name: nas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.nas_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.nas_id_seq OWNED BY public.nas.id;


--
-- Name: nasreload; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.nasreload (
    nasipaddress inet NOT NULL,
    reloadtime timestamp with time zone NOT NULL
);


--
-- Name: radacct; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radacct (
    radacctid bigint NOT NULL,
    acctsessionid text NOT NULL,
    acctuniqueid text NOT NULL,
    username text,
    groupname text,
    realm text,
    nasipaddress inet NOT NULL,
    nasportid text,
    nasporttype text,
    acctstarttime timestamp with time zone,
    acctupdatetime timestamp with time zone,
    acctstoptime timestamp with time zone,
    acctinterval bigint,
    acctsessiontime bigint,
    acctauthentic text,
    connectinfo_start text,
    connectinfo_stop text,
    acctinputoctets bigint,
    acctoutputoctets bigint,
    calledstationid text,
    callingstationid text,
    acctterminatecause text,
    servicetype text,
    framedprotocol text,
    framedipaddress inet,
    framedipv6address inet,
    framedipv6prefix inet,
    framedinterfaceid text,
    delegatedipv6prefix inet,
    class text
);


--
-- Name: radacct_radacctid_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radacct_radacctid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radacct_radacctid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radacct_radacctid_seq OWNED BY public.radacct.radacctid;


--
-- Name: radcheck; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radcheck (
    id integer NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    attribute text DEFAULT ''::text NOT NULL,
    op character varying(2) DEFAULT '=='::character varying NOT NULL,
    value text DEFAULT ''::text NOT NULL
);


--
-- Name: radcheck_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radcheck_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radcheck_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radcheck_id_seq OWNED BY public.radcheck.id;


--
-- Name: radgroupcheck; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radgroupcheck (
    id integer NOT NULL,
    groupname text DEFAULT ''::text NOT NULL,
    attribute text DEFAULT ''::text NOT NULL,
    op character varying(2) DEFAULT '=='::character varying NOT NULL,
    value text DEFAULT ''::text NOT NULL
);


--
-- Name: radgroupcheck_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radgroupcheck_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radgroupcheck_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radgroupcheck_id_seq OWNED BY public.radgroupcheck.id;


--
-- Name: radgroupreply; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radgroupreply (
    id integer NOT NULL,
    groupname text DEFAULT ''::text NOT NULL,
    attribute text DEFAULT ''::text NOT NULL,
    op character varying(2) DEFAULT '='::character varying NOT NULL,
    value text DEFAULT ''::text NOT NULL
);


--
-- Name: radgroupreply_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radgroupreply_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radgroupreply_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radgroupreply_id_seq OWNED BY public.radgroupreply.id;


--
-- Name: radpostauth; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radpostauth (
    id bigint NOT NULL,
    username text NOT NULL,
    pass text,
    reply text,
    calledstationid text,
    callingstationid text,
    authdate timestamp with time zone DEFAULT now() NOT NULL,
    class text
);


--
-- Name: radpostauth_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radpostauth_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radpostauth_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radpostauth_id_seq OWNED BY public.radpostauth.id;


--
-- Name: radreply; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radreply (
    id integer NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    attribute text DEFAULT ''::text NOT NULL,
    op character varying(2) DEFAULT '='::character varying NOT NULL,
    value text DEFAULT ''::text NOT NULL
);


--
-- Name: radreply_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radreply_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radreply_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radreply_id_seq OWNED BY public.radreply.id;


--
-- Name: radusergroup; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.radusergroup (
    id integer NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    groupname text DEFAULT ''::text NOT NULL,
    priority integer DEFAULT 0 NOT NULL
);


--
-- Name: radusergroup_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.radusergroup_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: radusergroup_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.radusergroup_id_seq OWNED BY public.radusergroup.id;


--
-- Name: admin_users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_users ALTER COLUMN id SET DEFAULT nextval('public.admin_users_id_seq'::regclass);


--
-- Name: billing_customers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_customers ALTER COLUMN id SET DEFAULT nextval('public.billing_customers_id_seq'::regclass);


--
-- Name: billing_invoices id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices ALTER COLUMN id SET DEFAULT nextval('public.billing_invoices_id_seq'::regclass);


--
-- Name: billing_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_packages ALTER COLUMN id SET DEFAULT nextval('public.billing_packages_id_seq'::regclass);


--
-- Name: billing_payments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_payments ALTER COLUMN id SET DEFAULT nextval('public.billing_payments_id_seq'::regclass);


--
-- Name: mikrotik_credentials id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mikrotik_credentials ALTER COLUMN id SET DEFAULT nextval('public.mikrotik_credentials_id_seq'::regclass);


--
-- Name: nas id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nas ALTER COLUMN id SET DEFAULT nextval('public.nas_id_seq'::regclass);


--
-- Name: radacct radacctid; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radacct ALTER COLUMN radacctid SET DEFAULT nextval('public.radacct_radacctid_seq'::regclass);


--
-- Name: radcheck id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radcheck ALTER COLUMN id SET DEFAULT nextval('public.radcheck_id_seq'::regclass);


--
-- Name: radgroupcheck id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radgroupcheck ALTER COLUMN id SET DEFAULT nextval('public.radgroupcheck_id_seq'::regclass);


--
-- Name: radgroupreply id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radgroupreply ALTER COLUMN id SET DEFAULT nextval('public.radgroupreply_id_seq'::regclass);


--
-- Name: radpostauth id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radpostauth ALTER COLUMN id SET DEFAULT nextval('public.radpostauth_id_seq'::regclass);


--
-- Name: radreply id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radreply ALTER COLUMN id SET DEFAULT nextval('public.radreply_id_seq'::regclass);


--
-- Name: radusergroup id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radusergroup ALTER COLUMN id SET DEFAULT nextval('public.radusergroup_id_seq'::regclass);


--
-- Name: admin_users admin_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_pkey PRIMARY KEY (id);


--
-- Name: admin_users admin_users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_username_key UNIQUE (username);


--
-- Name: billing_customers billing_customers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_customers
    ADD CONSTRAINT billing_customers_pkey PRIMARY KEY (id);


--
-- Name: billing_invoices billing_invoices_invoice_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_invoice_number_key UNIQUE (invoice_number);


--
-- Name: billing_invoices billing_invoices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_pkey PRIMARY KEY (id);


--
-- Name: billing_packages billing_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_packages
    ADD CONSTRAINT billing_packages_pkey PRIMARY KEY (id);


--
-- Name: billing_payments billing_payments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_payments
    ADD CONSTRAINT billing_payments_pkey PRIMARY KEY (id);


--
-- Name: mikrotik_credentials mikrotik_credentials_nas_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mikrotik_credentials
    ADD CONSTRAINT mikrotik_credentials_nas_id_key UNIQUE (nas_id);


--
-- Name: mikrotik_credentials mikrotik_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mikrotik_credentials
    ADD CONSTRAINT mikrotik_credentials_pkey PRIMARY KEY (id);


--
-- Name: nas nas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nas
    ADD CONSTRAINT nas_pkey PRIMARY KEY (id);


--
-- Name: nasreload nasreload_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.nasreload
    ADD CONSTRAINT nasreload_pkey PRIMARY KEY (nasipaddress);


--
-- Name: radacct radacct_acctuniqueid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radacct
    ADD CONSTRAINT radacct_acctuniqueid_key UNIQUE (acctuniqueid);


--
-- Name: radacct radacct_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radacct
    ADD CONSTRAINT radacct_pkey PRIMARY KEY (radacctid);


--
-- Name: radcheck radcheck_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radcheck
    ADD CONSTRAINT radcheck_pkey PRIMARY KEY (id);


--
-- Name: radgroupcheck radgroupcheck_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radgroupcheck
    ADD CONSTRAINT radgroupcheck_pkey PRIMARY KEY (id);


--
-- Name: radgroupreply radgroupreply_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radgroupreply
    ADD CONSTRAINT radgroupreply_pkey PRIMARY KEY (id);


--
-- Name: radpostauth radpostauth_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radpostauth
    ADD CONSTRAINT radpostauth_pkey PRIMARY KEY (id);


--
-- Name: radreply radreply_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radreply
    ADD CONSTRAINT radreply_pkey PRIMARY KEY (id);


--
-- Name: radusergroup radusergroup_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.radusergroup
    ADD CONSTRAINT radusergroup_pkey PRIMARY KEY (id);


--
-- Name: idx_billing_customers_package; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_customers_package ON public.billing_customers USING btree (package_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_billing_customers_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_customers_status ON public.billing_customers USING btree (status) WHERE (deleted_at IS NULL);


--
-- Name: idx_billing_invoices_customer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_invoices_customer ON public.billing_invoices USING btree (customer_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_billing_invoices_period; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_invoices_period ON public.billing_invoices USING btree (period_year, period_month) WHERE (deleted_at IS NULL);


--
-- Name: idx_billing_invoices_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_invoices_status ON public.billing_invoices USING btree (status) WHERE (deleted_at IS NULL);


--
-- Name: idx_billing_packages_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_packages_active ON public.billing_packages USING btree (is_active) WHERE (deleted_at IS NULL);


--
-- Name: idx_billing_packages_deleted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_packages_deleted ON public.billing_packages USING btree (deleted_at);


--
-- Name: idx_billing_payments_invoice; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_billing_payments_invoice ON public.billing_payments USING btree (invoice_id) WHERE (deleted_at IS NULL);


--
-- Name: idx_customers_due_day; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_customers_due_day ON public.billing_customers USING btree (due_day);


--
-- Name: idx_invoices_due_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_invoices_due_date ON public.billing_invoices USING btree (due_date);


--
-- Name: nas_nasname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX nas_nasname ON public.nas USING btree (nasname);


--
-- Name: radacct_active_session_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radacct_active_session_idx ON public.radacct USING btree (acctuniqueid) WHERE (acctstoptime IS NULL);


--
-- Name: radacct_bulk_close; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radacct_bulk_close ON public.radacct USING btree (nasipaddress, acctstarttime) WHERE (acctstoptime IS NULL);


--
-- Name: radacct_bulk_timeout; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radacct_bulk_timeout ON public.radacct USING btree (acctstoptime NULLS FIRST, acctupdatetime);


--
-- Name: radacct_start_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radacct_start_user_idx ON public.radacct USING btree (acctstarttime, username);


--
-- Name: radcheck_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radcheck_username ON public.radcheck USING btree (username, attribute);


--
-- Name: radgroupcheck_groupname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radgroupcheck_groupname ON public.radgroupcheck USING btree (groupname, attribute);


--
-- Name: radgroupreply_groupname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radgroupreply_groupname ON public.radgroupreply USING btree (groupname, attribute);


--
-- Name: radreply_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radreply_username ON public.radreply USING btree (username, attribute);


--
-- Name: radusergroup_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX radusergroup_username ON public.radusergroup USING btree (username);


--
-- Name: billing_invoices trigger_generate_invoice_number; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_generate_invoice_number BEFORE INSERT ON public.billing_invoices FOR EACH ROW EXECUTE FUNCTION public.generate_invoice_number();


--
-- Name: billing_customers trigger_update_billing_customers_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_update_billing_customers_updated_at BEFORE UPDATE ON public.billing_customers FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: billing_invoices trigger_update_billing_invoices_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_update_billing_invoices_updated_at BEFORE UPDATE ON public.billing_invoices FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: billing_packages trigger_update_billing_packages_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_update_billing_packages_updated_at BEFORE UPDATE ON public.billing_packages FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: billing_payments trigger_update_billing_payments_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_update_billing_payments_updated_at BEFORE UPDATE ON public.billing_payments FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: billing_customers billing_customers_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_customers
    ADD CONSTRAINT billing_customers_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.billing_packages(id);


--
-- Name: billing_invoices billing_invoices_customer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_customer_id_fkey FOREIGN KEY (customer_id) REFERENCES public.billing_customers(id);


--
-- Name: billing_invoices billing_invoices_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.billing_packages(id);


--
-- Name: billing_payments billing_payments_invoice_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.billing_payments
    ADD CONSTRAINT billing_payments_invoice_id_fkey FOREIGN KEY (invoice_id) REFERENCES public.billing_invoices(id);


--
-- Name: mikrotik_credentials mikrotik_credentials_nas_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mikrotik_credentials
    ADD CONSTRAINT mikrotik_credentials_nas_id_fkey FOREIGN KEY (nas_id) REFERENCES public.nas(id) ON DELETE CASCADE;


--
-- =============================================================================
-- DEFAULT ADMIN USER
-- Username: admin
-- Password: admin123
-- =============================================================================

INSERT INTO admin_users (username, password_hash, full_name, role, is_active) 
VALUES ('admin', 'scrypt:32768:8:1$vFRJwsglT5kUjd3Y$f8990331324d261ba54588e58e257f791ce506856617fbb523fe05860a256720284e6a019a8991c588bc9821f165ad40964a9df43951ac75e4b2c2c160a0b9dc', 'Administrator', 'admin', true);

-- Database setup complete
