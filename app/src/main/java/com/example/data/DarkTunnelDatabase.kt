package com.example.data

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import android.content.Context
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "imported_configs")
data class ImportedConfigEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val fileName: String,
    val formatExtension: String,
    val fileSizeBytes: Long,
    val sha256Checksum: String,
    val shannonEntropy: Double,
    val detectedState: String, // ENCRYPTED, COMPRESSED, ENCODED, READABLE_JSON, CORRUPTED
    val algorithmSummary: String,
    val backupFilePath: String,
    val unlockedContent: String?,
    val timestamp: Long = System.currentTimeMillis()
)

@Entity(tableName = "operation_history")
data class OperationHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val category: String, // IMPORT, UNLOCK, DECODE, RECOVERY, GENERATE, EDIT, VPN
    val targetName: String,
    val status: String, // SUCCESS, FAILED, WARNING, INFO
    val details: String,
    val timestamp: Long = System.currentTimeMillis()
)

@Entity(tableName = "password_hints")
data class PasswordHintEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val label: String,
    val candidatePassword: String,
    val notes: String,
    val createdAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "saved_templates")
data class SavedTemplateEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val name: String,
    val protocol: String, // SSH, WEBSOCKET, TLS,SSH_WS_TLS, V2RAY_JSON
    val serverHost: String,
    val serverPort: Int,
    val username: String,
    val sniHost: String,
    val wsPath: String,
    val customPayload: String,
    val rawConfigJson: String,
    val isVerifiedReachable: Boolean = false,
    val lastVerifiedLatencyMs: Long? = null,
    val createdAt: Long = System.currentTimeMillis()
)

@Dao
interface DarkTunnelDao {
    @Query("SELECT * FROM imported_configs ORDER BY timestamp DESC")
    fun getAllImportedConfigs(): Flow<List<ImportedConfigEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertImportedConfig(config: ImportedConfigEntity): Long

    @Query("DELETE FROM imported_configs WHERE id = :id")
    suspend fun deleteImportedConfig(id: Int)

    @Query("SELECT * FROM operation_history ORDER BY timestamp DESC")
    fun getAllHistory(): Flow<List<OperationHistoryEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertHistory(entry: OperationHistoryEntity)

    @Query("DELETE FROM operation_history")
    suspend fun clearAllHistory()

    @Query("SELECT * FROM password_hints ORDER BY createdAt DESC")
    fun getAllPasswordHints(): Flow<List<PasswordHintEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPasswordHint(hint: PasswordHintEntity)

    @Query("DELETE FROM password_hints WHERE id = :id")
    suspend fun deletePasswordHint(id: Int)

    @Query("SELECT * FROM saved_templates ORDER BY createdAt DESC")
    fun getAllTemplates(): Flow<List<SavedTemplateEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertTemplate(template: SavedTemplateEntity): Long

    @Query("DELETE FROM saved_templates WHERE id = :id")
    suspend fun deleteTemplate(id: Int)
}

@Database(
    entities = [
        ImportedConfigEntity::class,
        OperationHistoryEntity::class,
        PasswordHintEntity::class,
        SavedTemplateEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class DarkTunnelDatabase : RoomDatabase() {
    abstract fun dao(): DarkTunnelDao

    companion object {
        @Volatile
        private var INSTANCE: DarkTunnelDatabase? = null

        fun getDatabase(context: Context): DarkTunnelDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    DarkTunnelDatabase::class.java,
                    "dark_tunnel_workbench.db"
                ).fallbackToDestructiveMigration(dropAllTables = true).build()
                INSTANCE = instance
                instance
            }
        }
    }
}

class DarkTunnelRepository(private val dao: DarkTunnelDao) {
    val importedConfigs: Flow<List<ImportedConfigEntity>> = dao.getAllImportedConfigs()
    val operationHistory: Flow<List<OperationHistoryEntity>> = dao.getAllHistory()
    val passwordHints: Flow<List<PasswordHintEntity>> = dao.getAllPasswordHints()
    val savedTemplates: Flow<List<SavedTemplateEntity>> = dao.getAllTemplates()

    suspend fun addImportedConfig(config: ImportedConfigEntity): Long = dao.insertImportedConfig(config)
    suspend fun removeImportedConfig(id: Int) = dao.deleteImportedConfig(id)

    suspend fun logOperation(category: String, targetName: String, status: String, details: String) {
        dao.insertHistory(
            OperationHistoryEntity(
                category = category,
                targetName = targetName,
                status = status,
                details = details
            )
        )
    }

    suspend fun clearHistory() = dao.clearAllHistory()

    suspend fun addPasswordHint(label: String, candidatePassword: String, notes: String) {
        dao.insertPasswordHint(
            PasswordHintEntity(
                label = label,
                candidatePassword = candidatePassword,
                notes = notes
            )
        )
    }

    suspend fun removePasswordHint(id: Int) = dao.deletePasswordHint(id)

    suspend fun saveTemplate(template: SavedTemplateEntity): Long = dao.insertTemplate(template)
    suspend fun removeTemplate(id: Int) = dao.deleteTemplate(id)
}
