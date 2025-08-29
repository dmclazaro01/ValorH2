// TEST
import org.apache.poi.ss.usermodel.{CellType, Sheet, WorkbookFactory}
import org.json.{JSONArray, JSONObject}
import org.junit.Test
import org.specs2.control.Properties.aProperty

import java.io.{File, FileInputStream, FileOutputStream, IOException}
import java.net.URL
import java.nio.channels.{Channels, ReadableByteChannel}
import scala.collection.JavaConverters._
import scala.collection.mutable

/**
 * Created by yipi on 29/06/22.
 * javigp@usal.es
 * yipi
 */

class scalaProcessorAPTs {

  @Test
  def testOnTrigger(): Unit = {
    val urlDownload = "https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pub?output=xlsx"
    downloadUsingNIO(urlDownload, "apt_notes.xlsx")
    val countries = Map("China" -> 17, "Russia" -> 22, "North Korea" -> 23, "Iran" -> 15, "Israel" -> 7, "NATO" -> 12, "Middle East" -> 9, "Others" -> 12)
    val countryResults = mutable.Map[String, Map[String, String]]()
    val workbook = WorkbookFactory.create(new File("apt_notes.xlsx"))
    val results = countries.map { case (country, columnNumber) =>
      val sheet = workbook.getSheet(country)
      val commonNames = getColumnData(sheet, country)
      val tools = getColumnData(sheet, s"Unnamed: $columnNumber")
      tools.foreach{tool =>
        println(tool)
      }
      val result = commonNames.zip(tools).toMap
      country -> result
    }


    countries.foreach { case (country, columnIndex) =>
      val inputStream = new FileInputStream("apt_notes.xlsx")
      val workbook = WorkbookFactory.create(inputStream)
      val sheet = workbook.getSheet(country)

      val commonNamesColumn = if (country == "Others") "Other Actors" else country
      val commonNames = sheet.rowIterator().asScala.drop(1).map { row =>
        Option(row.getCell(sheet.getRow(0).getFirstCellNum)).flatMap { cell =>
          if (cell.getStringCellValue == commonNamesColumn) {
            Option(row.getCell(cell.getColumnIndex)).map(_.getStringCellValue).getOrElse("null")
          }else "None"
        }
      }.filter(_.isDefined).map(_.get).toList

      val tools = sheet.rowIterator().asScala.drop(1).map { row =>
        Option(row.getCell(columnIndex)).map(cell =>
          if (cell.getCellType == CellType.STRING) cell.getStringCellValue
          else if (cell.getCellType == CellType.NUMERIC) cell.getNumericCellValue.toString
          else "null"
        ).getOrElse("null")
      }.toList

      val result = (commonNames zip tools).toMap

      countryResults(country) = result
      inputStream.close()
    }

    // JSON String
    val jsonString = "{\"source\":\"threat_intel\",\"asset\":{},\"message\":{\"malware_alias\":[],\"malware\":\"win.poison\",\"iocs\":[{\"urls\":[\"https://g.bing.com/neg/0?action=emptycreativeimpression&adUnitId=11730597&publisherId=251978541&rid=c49daf0978374fadaedc3e4010ecf8e3&localId=w:09BE301F-AF04-8909-0529-ADD134954281&deviceId=6896190259413427&anid=\",\"https://g.bing.com/neg/0?action=emptycreative&adUnitId=11730597&publisherId=251978541&rid=c49daf0978374fadaedc3e4010ecf8e3&localId=w:09BE301F-AF04-8909-0529-ADD134954281&deviceId=6896190259413427&anid=\"],\"domains\":[\"2.tcp.eu.ngrok.io\",\"85.177.190.20.in-addr.arpa\",\"240.221.184.93.in-addr.arpa\",\"9.228.82.20.in-addr.arpa\",\"g.bing.com\",\"200.197.79.204.in-addr.arpa\",\"41.110.16.96.in-addr.arpa\",\"55.36.223.20.in-addr.arpa\",\"95.221.229.192.in-addr.arpa\",\"57.138.127.3.in-addr.arpa\",\"86.23.85.13.in-addr.arpa\",\"198.187.3.20.in-addr.arpa\",\"18.134.221.88.in-addr.arpa\",\"23.236.111.52.in-addr.arpa\",\"178.223.142.52.in-addr.arpa\",\"180.178.17.96.in-addr.arpa\",\"105.193.132.51.in-addr.arpa\"],\"ips\":[\"8.8.8.8\",\"3.127.138.57\",\"18.197.239.5\",\"18.156.13.209\",\"138.91.171.81\",\"204.79.197.200\"]}],\"vulnerability\":\"{}\",\"tool\":\"{}\",\"tactic\":[\"T1543.003\"],\"SHA256\":\"c93ab6bb562f09706d141a4804e655fe92612a07bc3ab92bf1f6f7a7a9ef9dcc\",\"relationships\":\"{}\",\"threat_actor\":\"[]\",\"ioctype\":\"\",\"techniques\":[\"T1102\",\"T1012\",\"T1082\"],\"threat_type\":\"botnet_cc\",\"family\":[\"njrat\"],\"asset\":\"1222664\",\"desc\":\"Widely used RAT written in .NET.\"}}"

    // Parse JSON String to JSONObject
    val data = new JSONObject(jsonString)

    // Extract 'malware' value from JSON
    val malwareValue = data.getJSONObject("message").getString("malware").split('.').last.toUpperCase

    // Logic to work with Excel data and malware value
    val apts = results.flatMap { case (country, tools) =>
      tools.collect { case (toolName, toolValue) if toolValue.toUpperCase.strip().contains(malwareValue.toUpperCase().strip()) => toolName }
    }.toList

    // Update JSON object with found threat actors
    data.getJSONObject("message").put("threat_actor", new JSONArray(apts.asJava))

    // Print updated JSON object
    println(data.toString(4)) // Pretty print with indentation
  }

  def getColumnData(sheet: Sheet, columnName: String): List[String] = {
    // Encuentra el índice de la columna por el nombre de la columna
    val headerRow = sheet.getRow(0)
    val columnIdx = (0 until headerRow.getLastCellNum).find(i => Option(headerRow.getCell(i)).exists(_.getStringCellValue == columnName)).getOrElse(-1)
    if (columnIdx == -1) {
      List.empty[String] // Retorna una lista vacía si no se encuentra la columna
    } else {
      sheet.iterator.asScala.toList.flatMap { row =>
        Option(row.getCell(columnIdx)).map(_.getStringCellValue)
      }.drop(1) // Descarta el encabezado
    }
  }

  @throws[IOException]
  def downloadUsingNIO(urlStr: String, file: String): Unit = {
    val url : URL = new URL(urlStr)
    val rbc : ReadableByteChannel = Channels.newChannel(url.openStream())
    val fos : FileOutputStream = new FileOutputStream(file)
    fos.getChannel.transferFrom(rbc, 0, Long.MaxValue)
    fos.close()
    rbc.close()
  }
}