<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output omit-xml-declaration="yes" indent="yes"/>
  <xsl:template match="node()|@*">
    <xsl:copy><xsl:apply-templates select="node()|@*"/></xsl:copy>
  </xsl:template>
  <xsl:template match="/domain/on_poweroff"/>
  <xsl:template match="/domain/devices/graphics|/domain/devices/video"/>
  <xsl:template match="/domain">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
      <on_poweroff>restart</on_poweroff>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
