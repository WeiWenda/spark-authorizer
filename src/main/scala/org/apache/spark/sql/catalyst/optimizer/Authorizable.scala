/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.sql.catalyst.optimizer

import com.githup.yaooqinn.spark.authorizer.Logging
import org.apache.hadoop.hive.ql.plan.HiveOperation
import org.apache.hadoop.hive.ql.security.authorization.plugin.{HiveAuthzContext, HiveOperationType}

import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.catalyst.plans.logical.{Command, LogicalPlan}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.command._
import org.apache.spark.sql.hive.{HiveExternalCatalog, PrivilegesBuilder}
import org.apache.spark.sql.hive.client.AuthzImpl

trait Authorizable extends Rule[LogicalPlan] with Logging {

  def spark: SparkSession

  /**
   * Visit the [[LogicalPlan]] recursively to get all hive privilege objects, check the privileges
   * using Hive Authorizer V2 which provide sql based authorization and can implements
   * ranger-hive-plugins.
   * If the user is authorized, then the original plan will be returned; otherwise, interrupted by
   * some particular privilege exceptions.
   * @param plan a spark LogicalPlan for verifying privileges
   * @return a plan itself which has gone through the privilege check.
   */
  override def apply(plan: LogicalPlan): LogicalPlan = {
    val operationType: HiveOperationType = getOperationType(plan)
    val authzContext = new HiveAuthzContext.Builder().build()
    val (in, out) = PrivilegesBuilder.build(plan)
    spark.sharedState.externalCatalog match {
      case _: HiveExternalCatalog =>
        AuthzImpl.checkPrivileges(spark, operationType, in, out, authzContext)
      case _ =>
    }
    // iff no exception.
    // We just return the original plan here, so this rule will be executed only once.
    plan
  }

//  def policyCacheDir: Option[String] = {
//    Option(spark.sparkContext.hadoopConfiguration.get("ranger.plugin.hive.policy.cache.dir"))
//  }
//
//
//  def createCacheDirIfNonExists(dir: String): Unit = {
//    val file = new File(dir)
//    if (!file.exists()) {
//      if (file.mkdirs()) {
//        info("Creating ranger policy cache directory at " + file.getAbsolutePath)
//        file.deleteOnExit()
//      } else {
//        warn("Unable to create ranger policy cache directory at " + file.getAbsolutePath)
//      }
//    }
//  }
//
//  policyCacheDir match {
//    case Some(dir) => createCacheDirIfNonExists(dir)
//    case _ =>
//      // load resources from ranger configuration files
//      Option(Utils.getContextOrSparkClassLoader.getResource("ranger-hive-security.xml")) match {
//        case Some(url) =>
//          spark.sparkContext.hadoopConfiguration.addResource(url)
//          policyCacheDir match {
//            case Some(dir) => createCacheDirIfNonExists(dir)
//            case _ =>
//          }
//        case _ =>
//      }
//  }

  /**
   * Mapping of [[LogicalPlan]] -> [[HiveOperation]]
   * @param plan a spark LogicalPlan
   * @return
   */
  def getHiveOperation(plan: LogicalPlan): HiveOperation = {
    plan match {
      case c: Command => c.nodeName.replaceAll("XSQL", "") match {
        case "AlterDatabasePropertiesCommand" => HiveOperation.ALTERDATABASE
        case "AlterTableAddColumnsCommand" => HiveOperation.ALTERTABLE_ADDCOLS
        case "AlterTableAddPartitionCommand" => HiveOperation.ALTERTABLE_ADDPARTS
        case "AlterTableChangeColumnCommand" => HiveOperation.ALTERTABLE_RENAMECOL
        case "AlterTableDropPartitionCommand" => HiveOperation.ALTERTABLE_DROPPARTS
        case "AlterTableRecoverPartitionsCommand" => HiveOperation.MSCK
        case "AlterTableRenamePartitionCommand" => HiveOperation.ALTERTABLE_RENAMEPART
        case "AlterTableRenameCommand" =>
          if (!c.asInstanceOf[AlterTableRenameCommand].isView) {
            HiveOperation.ALTERTABLE_RENAME
          } else {
            HiveOperation.ALTERVIEW_RENAME
          }
        case "AlterTableSetPropertiesCommand"
             | "AlterTableUnsetPropertiesCommand" => HiveOperation.ALTERTABLE_PROPERTIES
        case "AlterTableSerDePropertiesCommand" => HiveOperation.ALTERTABLE_SERDEPROPERTIES
        case "AlterTableSetLocationCommand" => HiveOperation.ALTERTABLE_LOCATION
        case "AlterViewAsCommand" => HiveOperation.QUERY
        // case _: AlterViewAsCommand => HiveOperation.ALTERVIEW_AS

        case "AnalyzeColumnCommand" => HiveOperation.QUERY
        // case _: AnalyzeTableCommand => HiveOperation.ANALYZE_TABLE
        // Hive treat AnalyzeTableCommand as QUERY, obey it.
        case "AnalyzeTableCommand" => HiveOperation.QUERY
        case "AnalyzePartitionCommand" => HiveOperation.QUERY

        case "CreateDatabaseCommand" => HiveOperation.CREATEDATABASE
        case "CreateDataSourceTableAsSelectCommand"
             | "CreateHiveTableAsSelectCommand" => HiveOperation.CREATETABLE_AS_SELECT
        case "CreateFunctionCommand" => HiveOperation.CREATEFUNCTION
        case "CreateTableCommand"
             | "CreateDataSourceTableCommand" => HiveOperation.CREATETABLE
        case "CreateTableLikeCommand" => HiveOperation.CREATETABLE
        case "CreateViewCommand"
             | "CacheTableCommand"
             | "CreateTempViewUsing" => HiveOperation.CREATEVIEW

        case "DescribeColumnCommand" => HiveOperation.DESCTABLE
        case "DescribeDatabaseCommand" => HiveOperation.DESCDATABASE
        case "DescribeFunctionCommand" => HiveOperation.DESCFUNCTION
        case "DescribeTableCommand" => HiveOperation.DESCTABLE

        case "DropDatabaseCommand" => HiveOperation.DROPDATABASE
        // Hive don't check privileges for `drop function command`, what about a unverified user
        // try to drop functions.
        // We treat permanent functions as tables for verifying.
        case "DropFunctionCommand" if !c.asInstanceOf[DropFunctionCommand].isTemp =>
          HiveOperation.DROPTABLE
        case "DropFunctionCommand" if c.asInstanceOf[DropFunctionCommand].isTemp =>
          HiveOperation.DROPFUNCTION
        case "DropTableCommand" => HiveOperation.DROPTABLE

        case "ExplainCommand" => getHiveOperation(c.asInstanceOf[ExplainCommand].logicalPlan)

        case "InsertIntoDataSourceCommand" => HiveOperation.QUERY
        case "InsertIntoDataSourceDirCommand" => HiveOperation.QUERY
        case "InsertIntoHadoopFsRelationCommand" => HiveOperation.CREATETABLE_AS_SELECT
        case "InsertIntoHiveDirCommand" => HiveOperation.QUERY
        case "InsertIntoHiveTable" => HiveOperation.QUERY

        case "LoadDataCommand" => HiveOperation.LOAD

        case "SaveIntoDataSourceCommand" => HiveOperation.QUERY
        case "SetCommand" if c.asInstanceOf[SetCommand].kv.isEmpty
          || c.asInstanceOf[SetCommand].kv.get._2.isEmpty =>
          HiveOperation.SHOWCONF
        case "SetDatabaseCommand" => HiveOperation.SWITCHDATABASE
        case "ShowCreateTableCommand" => HiveOperation.SHOW_CREATETABLE
        case "ShowColumnsCommand" => HiveOperation.SHOWCOLUMNS
        case "ShowDatabasesCommand" => HiveOperation.SHOWDATABASES
        case "ShowFunctionsCommand" => HiveOperation.SHOWFUNCTIONS
        case "ShowPartitionsCommand" => HiveOperation.SHOWPARTITIONS
        case "ShowTablesCommand" => HiveOperation.SHOWTABLES
        case "ShowTablePropertiesCommand" => HiveOperation.SHOW_TBLPROPERTIES
        case "StreamingExplainCommand" =>
          getHiveOperation(c.asInstanceOf[StreamingExplainCommand].queryExecution.optimizedPlan)

        case "TruncateTableCommand" => HiveOperation.TRUNCATETABLE

        case "UncacheTableCommand" => HiveOperation.DROPVIEW

        // Commands that do not need build privilege goes as explain type
        case _ =>
          // AddFileCommand
          // AddJarCommand
          // ...
          HiveOperation.EXPLAIN
      }
      case _ => HiveOperation.QUERY
    }
  }

  def getOperationType(logicalPlan: LogicalPlan): HiveOperationType = {
    HiveOperationType.valueOf(getHiveOperation(logicalPlan).name())
  }
}
