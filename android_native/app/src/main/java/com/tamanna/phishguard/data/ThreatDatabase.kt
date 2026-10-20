package com.tamanna.phishguard.data

import android.content.Context
import androidx.room.*

/**
 * PhishGuard AI - Local On-Device Database (Room / SQLite)
 * Stores local threat logs, audit trails, and historical analytics.
 * Compliant with 8th Semester Mobile Computing Lab Proposal specifications.
 */

@Entity(tableName = "threat_logs")
data class ThreatEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestamp: Long,
    val sourceApp: String,
    val sender: String,
    val payloadPreview: String,
    val threatCategory: String,
    val riskScore: Double,
    val isAnomaly: Boolean
)

@Dao
interface ThreatDao {
    @Query("SELECT * FROM threat_logs ORDER BY timestamp DESC")
    suspend fun getAllThreats(): List<ThreatEntity>

    @Query("SELECT * FROM threat_logs WHERE riskScore >= 68.0 ORDER BY timestamp DESC")
    suspend fun getCriticalThreats(): List<ThreatEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertThreat(threat: ThreatEntity): Long

    @Query("DELETE FROM threat_logs")
    suspend fun clearAll()
}

@Database(entities = [ThreatEntity::class], version = 1, exportSchema = false)
abstract class ThreatDatabase : RoomDatabase() {
    abstract fun threatDao(): ThreatDao

    companion object {
        @Volatile
        private var INSTANCE: ThreatDatabase? = null

        fun getDatabase(context: Context): ThreatDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    ThreatDatabase::class.java,
                    "phishguard_threat_db"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
