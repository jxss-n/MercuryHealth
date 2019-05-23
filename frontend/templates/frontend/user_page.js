am4core.ready(function() {

  // Themes begin
  am4core.useTheme(am4themes_dataviz);
  am4core.useTheme(am4themes_animated);
  // Themes end

  // Create chart instance
  var chart = am4core.create("chartdiv", am4charts.XYChart);

  // Add data
  chart.data = [{
    "date": "2013-01-01",
    "value": 60
  }, {
    "date": "2013-01-02",
    "value": 67
  }, {
    "date": "2013-01-03",
    "value": 64
  }, {
    "date": "2013-01-04",
    "value": 66
  }, {
    "date": "2013-01-05",
    "value": 60
  }, {
    "date": "2013-01-06",
    "value": 63
  }, {
    "date": "2013-01-07",
    "value": 61
  }, {
    "date": "2013-01-08",
    "value": 60
  }, {
    "date": "2013-01-09",
    "value": 65
  }, {
    "date": "2013-01-10",
    "value": 75
  }, {
    "date": "2013-01-11",
    "value": 77
  }, {
    "date": "2013-01-12",
    "value": 78
  }, {
    "date": "2013-01-13",
    "value": 70
  }, {
    "date": "2013-01-14",
    "value": 70
  }, {
    "date": "2013-01-15",
    "value": 73
  }, {
    "date": "2013-01-16",
    "value": 71
  }, {
    "date": "2013-01-17",
    "value": 74
  }, {
    "date": "2013-01-18",
    "value": 78
  }, {
    "date": "2013-01-19",
    "value": 85
  }, {
    "date": "2013-01-20",
    "value": 82
  }, {
    "date": "2013-01-21",
    "value": 83
  }, {
    "date": "2013-01-22",
    "value": 88
  }, {
    "date": "2013-01-23",
    "value": 85
  }, {
    "date": "2013-01-24",
    "value": 85
  }, {
    "date": "2013-01-25",
    "value": 80
  }, {
    "date": "2013-01-26",
    "value": 87
  }, {
    "date": "2013-01-27",
    "value": 84
  }, {
    "date": "2013-01-28",
    "value": 83
  }, {
    "date": "2013-01-29",
    "value": 84
  }, {
    "date": "2013-01-30",
    "value": 81
  }];

  // Set input format for the dates
  chart.dateFormatter.inputDateFormat = "yyyy-MM-dd";

  // Create axes
  var dateAxis = chart.xAxes.push(new am4charts.DateAxis());
  var valueAxis = chart.yAxes.push(new am4charts.ValueAxis());

  // Create series
  var series = chart.series.push(new am4charts.LineSeries());
  series.dataFields.valueY = "value";
  series.dataFields.dateX = "date";
  series.tooltipText = "{value}"
  series.strokeWidth = 2;
  series.minBulletDistance = 15;

  // Drop-shaped tooltips
  series.tooltip.background.cornerRadius = 20;
  series.tooltip.background.strokeOpacity = 0;
  series.tooltip.pointerOrientation = "vertical";
  series.tooltip.label.minWidth = 40;
  series.tooltip.label.minHeight = 40;
  series.tooltip.label.textAlign = "middle";
  series.tooltip.label.textValign = "middle";

  // Make bullets grow on hover
  var bullet = series.bullets.push(new am4charts.CircleBullet());
  bullet.circle.strokeWidth = 2;
  bullet.circle.radius = 4;
  bullet.circle.fill = am4core.color("#fff");

  var bullethover = bullet.states.create("hover");
  bullethover.properties.scale = 1.3;

  // Make a panning cursor
  chart.cursor = new am4charts.XYCursor();
  chart.cursor.behavior = "panXY";
  chart.cursor.xAxis = dateAxis;
  chart.cursor.snapToSeries = series;

  // Create vertical scrollbar and place it before the value axis
  chart.scrollbarY = new am4core.Scrollbar();
  chart.scrollbarY.parent = chart.leftAxesContainer;
  chart.scrollbarY.toBack();

  // Create a horizontal scrollbar with previe and place it underneath the date axis
  chart.scrollbarX = new am4charts.XYChartScrollbar();
  chart.scrollbarX.series.push(series);
  chart.scrollbarX.parent = chart.bottomAxesContainer;

  chart.events.on("ready", function () {
    dateAxis.zoom({start:0.79, end:1});
  });

}); // end am4core.ready()
