#!/usr/bin/php
<?php

	require_once "Database.php";
	/**
	 * The Analyzer class.
	 */
 
	class Analyzer 
	{
 
		private $fp;
		private $db;
		private $stmt;
 
		public function __construct(Database $db) 
		{
			// create db object
			$this->db = $db;
		}
 
		public function __destruct() 
		{
			@fclose($this->fp);
			$this->db = null;
		}
 
		/**
		 * Load a MySQL slow log.
		 *
		 * @param string $file Slow query log file
		 */
 
		public function load($file, $append = false) 
		{
			// create the database
			$this->db->prepare("CREATE TABLE IF NOT EXISTS queries (id INTEGER NOT NULL, time INTEGER NOT NULL, user VARCHAR(128), host VARCHAR(512), ip VARCHAR(128), execute_time TEXT, lock_time TEXT, rows_sent INTEGER, rows_examined INTEGER, query TEXT, PRIMARY KEY (id))")->execute();
			// open up the slow log for reading
			$this->fp = fopen($file, 'rb');
			$this->stmt = $this->db->prepare("INSERT INTO queries (time, user, host, ip, execute_time, lock_time, rows_sent, rows_examined, query) VALUES (:time, :user, :host, :ip, :execute_time, :lock_time, :rows_sent, :rows_examined, :query)");
			// read off until first Time section
			while ($line = fgets($this->fp)) 
			{
				if (preg_match('/^# Time: (\d{6}) (\d{2}):(\d{2}):(\d{2})/', $line)) {
					$this->read_log_file($line);
					return;
				}
			}
		}
 
		/**
		 * Read a section of the slow query log.
		 *
		 * @param string $time_line The first line of the section (# Time)
		 */
 
		private function read_log_file($time_line) 
		{
			// parse datetime info
			preg_match("/^# Time:[ ]+(\d{6})[ ]+(\d{1,2}):(\d{1,2}):(\d{1,2})/", $time_line, $matches);
			$time = date(
				"U",
				mktime(
					$matches[2], // hour
					$matches[3], // minute
					$matches[4], // second
					substr($matches[1], 2, 2), // month
					substr($matches[1], 4, 2), // day
					substr($matches[1], 0, 2) // year
				)
			);
			$query = array();
			$raw_query = '';
			// read lines until next time section
			while ($line = fgets($this->fp)) 
			{
				if (preg_match('/^# Time: (\d{6}) (\d{2}):(\d{2}):(\d{2})/', $line)) 
				{
					$query['query'] = $raw_query;
					$this->stmt->execute($query);
					$this->read_log_file($line);
					return;
				} 
				elseif (preg_match('/^# User@Host: (\w+)\[\w+\] @ (.+) \[([^\[]*)\]/', $line, $matches)) 
				{
					if (!empty($raw_query)) 
					{
						$query['query'] = $raw_query;
						$this->stmt->execute($query);
						$query = array();
						$raw_query = '';
					}
					$query['time'] = $time;
					$query['user'] = $matches[1];
					$query['host'] = $matches[2];
					$query['ip'] = $matches[3];
				} 
				elseif (preg_match('/^# Query_time: ([\d|\.]+)\s+Lock_time: ([\d|\.]+)\s+Rows_sent: (\d+)\s+Rows_examined: (\d+)/', $line, $matches)) 
				{
					$query['execute_time'] = $matches[1];
					$query['lock_time'] = $matches[2];
					$query['rows_sent'] = $matches[3];
					$query['rows_examined'] = $matches[4];
				} 
				elseif (!preg_match('/^SET timestamp=/', $line) && !preg_match('/^use /', $line) && !preg_match('/^#/', $line)) 
				{
					// we want to get rid of SET timestamp
					// Percona adds extra data, for now let's ignore it
					$raw_query .= preg_replace('/^(\s{16}|\t{4})/', '', $line);
				}
			}
		}
 
		/**
		 * Return slow queries.
		 *
		 * @param array $opts Options for slow query results
		 */
 
		public function results($opts) 
		{
			$sql = "SELECT time,execute_time,lock_time,query FROM queries";
			$start = $opts['start'] ?: $opts['s'];
			$end = $opts['end'] ?: $opts['e'];
			$lock_time = $opts['lock-time'] ?: $opts['l'];
			$time = $opts['time'] ?: $opts['t'];
			$order = $opts['order'] ?: $opts['o'];
			$where = array();
			$params = array();
			if (!empty($start)) 
			{
				$where[] = "time >= :start";
				$params['start'] = date("U", strtotime($start));
			}
			if (!empty($end)) 
			{
				$where[] = "time <= :end";
				$params['end'] = date("U", strtotime($end));
			}
			if (!empty($lock_time)) 
			{
				$where[] = "lock_time >= :lock_time";
				$params['lock_time'] = $lock_time;
			}
			if (!empty($time)) 
			{
				$where[] = "execute_time >= :execute_time";
				$params['execute_time'] = $time;
			}
			if (!empty($where)) 
			{
				$sql .= " WHERE " . implode(" AND ", $where);
			}
			if (!empty($order)) {
				$sql .= " ORDER BY :order DESC";
				$params['order'] = $order;
			}
			$stmt = $this->db->prepare($sql);
			$stmt->execute($params);
			if (empty($opts['export'])) 
			{
				return $this->print_results($stmt);
			} 
			else 
			{
				return $this->export_results($opts['export'], $stmt);
			}
		}
 
		/**
		 * Print results to screen.
		 *
		 * @param object $stmt PDO prepared statement object
		 */
 
		private function print_results($stmt) 
		{
			$stmt->setFetchMode(PDO::FETCH_ASSOC);
			while ($row = $stmt->fetch()) 
			{
				echo sprintf("Time:           %s\n", date("Y-m-d H:i:s", $row['time']));
				echo sprintf("Execution Time: %s\n", $row['execute_time']);
				echo sprintf("Lock Time:      %s\n", $row['lock_time']);
				echo sprintf("Query:\n%s%s\n", $row['query'], str_pad('', 20, '-'));
			}
		}
 
		/**
		 * Export results to a CSV file.
		 *
		 * @param string $file CSV file.
		 * @param object $stmt PDO prepared statment object
		 */
 
		private function export_results($file, $stmt) 
		{
			$stmt->setFetchMode(PDO::FETCH_ASSOC);
			// open the csv for writing
			$csv = fopen($file, 'w');
			// set the headers
			fputcsv($csv, array('Date/Time', 'Execution Time', 'Lock Time', 'Query'));
			while ($row = $stmt->fetch()) 
			{
				fputcsv($csv, array(date("Y-m-d H:i:s", $row['time']), $row['execute_time'], $row['lock_time'], $row['query']));
			}
		}
 
	}
 
/**
 * The script.
 */
 
$opts = getopt('s:e:l:t:o:h', array('start:', 'end:', 'lock-time:', 'time:', 'export:', 'order:', 'skip-import', 'append', 'help'));
 
if (isset($opts['h']) || isset($opts['help'])) {
	echo <<<MAN
NAME
	slow-log-analyzer - Analyze a slow query log by date.
 
DESCRIPTION
	slow-log-analyzer was designed to quickly find slow queries between two dates/times. It works by scanning a slow query log and importing information to a sqlite database and then running queries against that. It is written in PHP and needs the PDO extension.
 
USAGE
	slow-log-analyzer [OPTIONS] [FILE]
 
OPTIONS
	-s, --start
		Show results later then this date.
 
	-e, --end
		Show results earlier then this date.
 
	-l, --lock-time
		Show only results that had a lock time greater then passed value.
 
	-t, --time
		Show only results that took greater then passed value.
 
	-o, --order
		Order results by field. (time, execute_time, lock_time)
 
	--skip-import
		Skip importing the log file into the db.
 
	--append
		Add slow log to current db (instead of clearing it).
 
	--export
		Export results (as CSV).
 
EXAMPLES:
	slow-log-analyzer /path/to/slow-query.log
		Default with no extra options.
 
	slow-log-analyzer --lock-time 3 /path/to/slow-query.log
		Show queries that locked for longer then 3 seconds.
 
	slow-log-analyzer --skip-import --start="5/28 9:00" --end="5/28 8:00"
		Don't reload the database, and find queries that were ran between 9 and 8 on 5/28
 
	slow-log-analyzer --export slow.csv /path/to/slow-query.log
		Export slow queries to a CSV file.
 
MAN;
	exit;
}

$db = new Database;
$analyzer = new Analyzer($db);


if (!isset($opts['skip-import'])) {
	$analyzer->load(array_pop($argv));
}
 
//$analyzer->results($opts);