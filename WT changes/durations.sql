DROP TABLE IF EXISTS durations;
CREATE TABLE durations (
  id serial NOT NULL,
  ip_id INTEGER,
  dwell_time INTERVAL NOT NULL,
  domain TEXT NOT NULL,
  url_id INTEGER,
  datetime TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

-- do these to speed up querying later:
CREATE INDEX ON durations (ip_id);
CREATE INDEX ON durations (domain);
CREATE INDEX ON durations (datetime);


-- 0A01002F is 10.1.0.47 in hex, without the leading x

INSERT INTO durations (ip_id, dwell_time, domain, url_id) VALUES
(log_getipid('0A01002F', 0), '234 SECONDS', 'www.example.com', log_geturlid('http', 'www.example.com', '', '/index.html', ''));


-- SELECT x'0A01002F'::bigint;
-- TRUNCATE durations RESTART IDENTITY;