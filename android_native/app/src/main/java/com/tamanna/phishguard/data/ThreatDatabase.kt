package com.tamanna.phishguard.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * PhishGuard AI - Local On-Device Database (SQLite Engine)
 * Stores local threat logs, audit trails, and historical analytics.
 * Fully compatible with standard Android SQLite without requiring complex kapt annotation processors.
 */

data class ThreatEntity(
    val id: Long = 0,
    val timestamp: Long,
    val sourceApp: String,
    val sender: String,
    val payloadPreview: String,
    val threatCategory: String,
    val riskScore: Double,
    val isAnomaly: Boolean
)

interface ThreatDao {
    fun getAllThreats(): List<ThreatEntity>
    fun getCriticalThreats(): List<ThreatEntity>
    fun insertThreat(threat: ThreatEntity): Long
    fun clearAll()
}

class ThreatDatabase private constructor(context: Context) : SQLiteOpenHelper(
    context.applicationContext,
    DATABASE_NAME,
    null,
    DATABASE_VERSION
) {
    private val dao = object : ThreatDao {
        override fun getAllThreats(): List<ThreatEntity> {
            val list = mutableListOf<ThreatEntity>()
            val db = readableDatabase
            val cursor = db.query(TABLE_NAME, null, null, null, null, null, "$COL_TIMESTAMP DESC")
            cursor.use {
                while (it.moveToNext()) {
                    list.add(
                        ThreatEntity(
                            id = it.getLong(it.getColumnIndexOrThrow(COL_ID)),
                            timestamp = it.getLong(it.getColumnIndexOrThrow(COL_TIMESTAMP)),
                            sourceApp = it.getString(it.getColumnIndexOrThrow(COL_APP)),
                            sender = it.getString(it.getColumnIndexOrThrow(COL_SENDER)),
                            payloadPreview = it.getString(it.getColumnIndexOrThrow(COL_PREVIEW)),
                            threatCategory = it.getString(it.getColumnIndexOrThrow(COL_CATEGORY)),
                            riskScore = it.getDouble(it.getColumnIndexOrThrow(COL_RISK)),
                            isAnomaly = it.getInt(it.getColumnIndexOrThrow(COL_ANOMALY)) == 1
                        )
                    )
                }
            }
            return list
        }

        override fun getCriticalThreats(): List<ThreatEntity> {
            val list = mutableListOf<ThreatEntity>()
            val db = readableDatabase
            val cursor = db.query(
                TABLE_NAME, null, "$COL_RISK >= ?", arrayOf("68.0"),
                null, null, "$COL_TIMESTAMP DESC"
            )
            cursor.use {
                while (it.moveToNext()) {
                    list.add(
                        ThreatEntity(
                            id = it.getLong(it.getColumnIndexOrThrow(COL_ID)),
                            timestamp = it.getLong(it.getColumnIndexOrThrow(COL_TIMESTAMP)),
                            sourceApp = it.getString(it.getColumnIndexOrThrow(COL_APP)),
                            sender = it.getString(it.getColumnIndexOrThrow(COL_SENDER)),
                            payloadPreview = it.getString(it.getColumnIndexOrThrow(COL_PREVIEW)),
                            threatCategory = it.getString(it.getColumnIndexOrThrow(COL_CATEGORY)),
                            riskScore = it.getDouble(it.getColumnIndexOrThrow(COL_RISK)),
                            isAnomaly = it.getInt(it.getColumnIndexOrThrow(COL_ANOMALY)) == 1
                        )
                    )
                }
            }
            return list
        }

        override fun insertThreat(threat: ThreatEntity): Long {
            val db = writableDatabase
            val values = ContentValues().apply {
                put(COL_TIMESTAMP, threat.timestamp)
                put(COL_APP, threat.sourceApp)
                put(COL_SENDER, threat.sender)
                put(COL_PREVIEW, threat.payloadPreview)
                put(COL_CATEGORY, threat.threatCategory)
                put(COL_RISK, threat.riskScore)
                put(COL_ANOMALY, if (threat.isAnomaly) 1 else 0)
            }
            return db.insert(TABLE_NAME, null, values)
        }

        override fun clearAll() {
            val db = writableDatabase
            db.delete(TABLE_NAME, null, null)
        }
    }

    fun threatDao(): ThreatDao = dao

    override fun onCreate(db: SQLiteDatabase) {
        val sql = """
            CREATE TABLE $TABLE_NAME (
                $COL_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COL_TIMESTAMP INTEGER NOT NULL,
                $COL_APP TEXT NOT NULL,
                $COL_SENDER TEXT NOT NULL,
                $COL_PREVIEW TEXT NOT NULL,
                $COL_CATEGORY TEXT NOT NULL,
                $COL_RISK REAL NOT NULL,
                $COL_ANOMALY INTEGER NOT NULL
            )
        """.trimIndent()
        db.execSQL(sql)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_NAME")
        onCreate(db)
    }

    companion object {
        private const val DATABASE_NAME = "phishguard_threat_db.db"
        private const val DATABASE_VERSION = 1
        private const val TABLE_NAME = "threat_logs"

        private const val COL_ID = "id"
        private const val COL_TIMESTAMP = "timestamp"
        private const val COL_APP = "source_app"
        private const val COL_SENDER = "sender"
        private const val COL_PREVIEW = "payload_preview"
        private const val COL_CATEGORY = "threat_category"
        private const val COL_RISK = "risk_score"
        private const val COL_ANOMALY = "is_anomaly"

        @Volatile
        private var INSTANCE: ThreatDatabase? = null

        fun getDatabase(context: Context): ThreatDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = ThreatDatabase(context)
                INSTANCE = instance
                instance
            }
        }
    }
}
