package org.kyberpipe.client.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assignment
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

enum class TabItem(val title: String) {
    HOME("Home"),
    FILES("Files"),
    CLIPBOARD("Clip"),
    NOTIFICATIONS("Alerts"),
    SETTINGS("Ops");

    fun getIcon(): ImageVector {
        return when (this) {
            HOME -> Icons.Default.Home
            FILES -> Icons.Default.Folder
            CLIPBOARD -> Icons.Default.Assignment
            NOTIFICATIONS -> Icons.Default.Notifications
            SETTINGS -> Icons.Default.Bolt
        }
    }
}

@Composable
fun BottomNavigationBar(
    selectedTab: TabItem,
    onTabSelected: (TabItem) -> Unit
) {
    val colors = MaterialTheme.colorScheme
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(65.dp)
            .background(colors.surface)
            .padding(horizontal = 8.dp),
        horizontalArrangement = Arrangement.SpaceAround,
        verticalAlignment = Alignment.CenterVertically
    ) {
        TabItem.values().forEach { tab ->
            val isSelected = tab == selectedTab
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight()
                    .clip(RoundedCornerShape(8.dp))
                    .clickable { onTabSelected(tab) }
                    .padding(vertical = 8.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Icon(
                    imageVector = tab.getIcon(),
                    contentDescription = tab.title,
                    tint = if (isSelected) colors.primary else colors.onSurface.copy(alpha = 0.6f),
                    modifier = Modifier.size(22.dp)
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = tab.title,
                    fontSize = 10.sp,
                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                    color = if (isSelected) colors.primary else colors.onSurface.copy(alpha = 0.6f)
                )
            }
        }
    }
}
