// Standard MTL Label - This code is used to generate a BT file for a standard
// MTL label when a new record is added to the MtlQueue table. It retrieves
// necessary data from related tables such as OrderRel, OrderDtl, Customer, and
// CustXPrt, and then constructs the content of the BT file based on this data.
// The file is saved to a specified location for use with Bartender software.

// Updated: 5-26-2026 - (https://github.com/dan-damit)

var mq = (from t in ttMtlQueue where t.RowMod == "A" select t).FirstOrDefault();
var or = (from r in Db.OrderRel where r.Company == mq.Company && r.OrderNum == mq.OrderNum && r.OrderLine == mq.OrderLine && r.OrderRelNum == mq.OrderRelNum select r).FirstOrDefault();
var od = (from r in Db.OrderDtl where r.Company == mq.Company && r.OrderNum == mq.OrderNum && r.OrderLine == mq.OrderLine select r).FirstOrDefault();
var c = (from r in Db.Customer where r.Company == mq.Company && r.CustNum == od.CustNum select r).FirstOrDefault();
var cx = (from r in Db.CustXPrt where r.Company == mq.Company && r.CustNum == od.CustNum && r.PartNum == mq.PartNum select r).FirstOrDefault();

try
{
     string printerName = "";
     string fileLoc = "";
     string Company_Company = Session.CompanyID;
     string Company_Name = Db.Company.Where(x => x.Company1 == Session.CompanyID).Select(x => x.Name).FirstOrDefault();
     string Customer_Character06 = c.Character06.ToString();
     string Customer_CustID = c.CustID.ToString();
     string MtlQueue_FromBinNum = mq.FromBinNum.ToString();
     string MtlQueue_IUM = mq.IUM.ToString();
     string MtlQueue_OrderLine = mq.OrderLine.ToString();
     string MtlQueue_OrderNum = mq.OrderNum.ToString();
     string MtlQueue_OrderRelNum = mq.OrderRelNum.ToString();
     string MtlQueue_PartNum = mq.PartNum;
     string MtlQueue_Quantity = mq.Quantity.ToString();
     string OrderDtl_POLine = od.POLine.ToString();
     string OrderDtl_RevisionNum = od.RevisionNum.ToString();
     string OrderDtl_ShortChar04 = od.ShortChar04.ToString();
     string OrderDtl_VMIAisle_c = od.VMIAisle_c.ToString();
     string OrderDtl_VMIColumn_c = od.VMIColumn_c.ToString();
     string OrderDtl_VMIRow_c = od.VMIRow_c.ToString();
     string OrderDtl_VMIWarehouse_c = od.VMIWarehouse_c.ToString();
     string OrderDtl_VMIZone_c = od.VMIZone_c.ToString();
     string OrderDtl_XPartNum = od.XPartNum.ToString();
     string OrderDtl_XRevisionNum = od.XRevisionNum.ToString();
     string OrderHed_PONum = Db.OrderHed.Where(x => x.Company == mq.Company && x.OrderNum == mq.OrderNum).Select(x => x.PONum.ToString()).FirstOrDefault();
     string OrderRel_Number01 = or.Number01.ToString();
     string OrderRel_Number02 = or.Number02.ToString();
     string OrderRel_ReqDate = or.ReqDate.ToString();
     string OrderRel_ShortChar02 = or.ShortChar02.ToString();
     string Part_ISOrigCountry = Db.Part.Where(x => x.Company == mq.Company && x.PartNum == mq.PartNum).Select(x => x.ISOrigCountry).FirstOrDefault();
     string Part_PartDescription = mq.PartDescription.Replace(",", " ").Replace("\n", "").Replace("\f", "").Replace("\r", "");
     string CustXPart_CustBin_c = (cx == null ? String.Empty : cx.CustBin_c.ToString());
     string btwLabel = (from u in Db.UDCodes where u.Company == Session.CompanyID && u.CodeTypeID == "BTFile" && u.CodeID == "PickLabel" select u).FirstOrDefault()["LongDesc"].ToString();

     foreach (var udc in (from u in Db.UDCodes where u.Company == mq.Company && u.CodeTypeID == "BTPrinter" && u.CodeID == Session.PlantID select u))
     {
          printerName = udc.LongDesc;
     }

     foreach (var BTLocation in (from u in Db.UDCodes where u.Company == mq.Company && u.CodeTypeID == "BTLocation" && u.CodeID == "Location" select u))
     {
          fileLoc = BTLocation.LongDesc;
     }

     string btFile = fileLoc + @"VACPICKLABEL_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + MtlQueue_OrderNum + MtlQueue_OrderLine + MtlQueue_OrderRelNum + ".BT";

     string barHeader = "%BTW% /AF=\"" + btwLabel + "\" /D=\"%Trigger File Name%\" /PRN=\"" + printerName + "\" /C=" + "1" + " /R=3 /P " + Environment.NewLine;
     barHeader += @"%END%" + Environment.NewLine;

     string line = "\"" + String.Join("\", \"", new[] {
          "Company_Company",
          "Company_Name",
          "Customer_Character06",
          "Customer_CustID",
          "MtlQueue_FromBinNum",
          "MtlQueue_IUM" ,
          "MtlQueue_OrderLine" ,
          "MtlQueue_OrderNum" ,
          "MtlQueue_OrderRelNum" ,
          "MtlQueue_PartNum" ,
          "MtlQueue_Quantity" ,
          "OrderDtl_POLine" ,
          "OrderDtl_RevisionNum" ,
          "OrderDtl_ShortChar04" ,
          "OrderDtl_VMIAisle_c" ,
          "OrderDtl_VMIColumn_c" ,
          "OrderDtl_VMIRow_c" ,
          "OrderDtl_VMIWarehouse_c" ,
          "OrderDtl_VMIZone_c" ,
          "OrderDtl_XPartNum" ,
          "OrderDtl_XRevisionNum" ,
          "OrderHed_PONum" ,
          "OrderRel_Number01" ,
          "OrderRel_Number02" ,
          "OrderRel_ReqDate" ,
          "OrderRel_ShortChar02" ,
          "Part_ISOrigCountry" ,
          "Part_PartDescription" ,
          "CustXPart_CustBin_c",
     }) + "\"" + Environment.NewLine;

     line += "\"" + String.Join("\", \"", new[] {
          Company_Company,
          Company_Name,
          Customer_Character06,
          Customer_CustID,
          MtlQueue_FromBinNum,
          MtlQueue_IUM,
          MtlQueue_OrderLine,
          MtlQueue_OrderNum,
          MtlQueue_OrderRelNum,
          MtlQueue_PartNum,
          MtlQueue_Quantity,
          OrderDtl_POLine,
          OrderDtl_RevisionNum,
          OrderDtl_ShortChar04,
          OrderDtl_VMIAisle_c,
          OrderDtl_VMIColumn_c,
          OrderDtl_VMIRow_c,
          OrderDtl_VMIWarehouse_c,
          OrderDtl_VMIZone_c,
          OrderDtl_XPartNum,
          OrderDtl_XRevisionNum,
          OrderHed_PONum,
          OrderRel_Number01,
          OrderRel_Number02,
          OrderRel_ReqDate,
          OrderRel_ShortChar02,
         Part_ISOrigCountry,
          Part_PartDescription,
          CustXPart_CustBin_c,
     }) + "\"";

     string btFileName = "VACPICKLABEL_"
         + DateTime.Now.ToString("yyyyMMdd_HHmmss")
         + MtlQueue_OrderNum
         + MtlQueue_OrderLine
         + MtlQueue_OrderRelNum
         + ".BT";

     string textToWriteToFile = barHeader + line;

     var BTOutFileTest = new FilePath(
         new FilePath(ServerFolder.FileShare),
         "Bartender",
         "EpicorOutput",
         btFileName
     );

     Sandbox.IO.File.WriteAllText(BTOutFileTest, textToWriteToFile);
}

catch (Exception ex)
{
     InfoMessage.Publish("Error creating BT File:\n" + ex.Message);
}
