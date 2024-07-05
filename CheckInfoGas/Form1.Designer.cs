namespace CheckInfoGas
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            btnStart = new System.Windows.Forms.Button();
            cbLQ = new System.Windows.Forms.CheckBox();
            cbInfo = new System.Windows.Forms.CheckBox();
            dgv = new System.Windows.Forms.DataGridView();
            cStt = new System.Windows.Forms.DataGridViewTextBoxColumn();
            cUsername = new System.Windows.Forms.DataGridViewTextBoxColumn();
            cPassword = new System.Windows.Forms.DataGridViewTextBoxColumn();
            cStatus = new System.Windows.Forms.DataGridViewTextBoxColumn();
            contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(components);
            importToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            numThread = new System.Windows.Forms.NumericUpDown();
            label1 = new System.Windows.Forms.Label();
            tbProxy = new System.Windows.Forms.TextBox();
            label2 = new System.Windows.Forms.Label();
            cbProxy = new System.Windows.Forms.CheckBox();
            tbApiKey = new System.Windows.Forms.TextBox();
            label3 = new System.Windows.Forms.Label();
            cbFo4 = new System.Windows.Forms.CheckBox();
            ((System.ComponentModel.ISupportInitialize)dgv).BeginInit();
            contextMenuStrip1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)numThread).BeginInit();
            SuspendLayout();
            // 
            // btnStart
            // 
            btnStart.Location = new System.Drawing.Point(11, 16);
            btnStart.Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            btnStart.Name = "btnStart";
            btnStart.Size = new System.Drawing.Size(111, 40);
            btnStart.TabIndex = 0;
            btnStart.Text = "Start";
            btnStart.UseVisualStyleBackColor = true;
            btnStart.Click += btnStart_Click;
            // 
            // cbLQ
            // 
            cbLQ.AutoSize = true;
            cbLQ.Enabled = false;
            cbLQ.Location = new System.Drawing.Point(394, 23);
            cbLQ.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            cbLQ.Name = "cbLQ";
            cbLQ.Size = new System.Drawing.Size(92, 24);
            cbLQ.TabIndex = 2;
            cbLQ.Tag = "";
            cbLQ.Text = "Check LQ";
            cbLQ.UseVisualStyleBackColor = true;
            // 
            // cbInfo
            // 
            cbInfo.AutoSize = true;
            cbInfo.Enabled = false;
            cbInfo.Location = new System.Drawing.Point(282, 23);
            cbInfo.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            cbInfo.Name = "cbInfo";
            cbInfo.Size = new System.Drawing.Size(100, 24);
            cbInfo.TabIndex = 3;
            cbInfo.Text = "Check Info";
            cbInfo.UseVisualStyleBackColor = true;
            // 
            // dgv
            // 
            dgv.AllowUserToAddRows = false;
            dgv.Anchor = System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            dgv.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            dgv.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            dgv.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] { cStt, cUsername, cPassword, cStatus });
            dgv.ContextMenuStrip = contextMenuStrip1;
            dgv.Location = new System.Drawing.Point(14, 72);
            dgv.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            dgv.Name = "dgv";
            dgv.RowHeadersVisible = false;
            dgv.RowHeadersWidth = 51;
            dgv.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            dgv.Size = new System.Drawing.Size(1486, 599);
            dgv.TabIndex = 1;
            // 
            // cStt
            // 
            cStt.FillWeight = 25F;
            cStt.HeaderText = "#";
            cStt.MinimumWidth = 6;
            cStt.Name = "cStt";
            // 
            // cUsername
            // 
            cUsername.FillWeight = 50F;
            cUsername.HeaderText = "Username";
            cUsername.MinimumWidth = 6;
            cUsername.Name = "cUsername";
            // 
            // cPassword
            // 
            cPassword.FillWeight = 50F;
            cPassword.HeaderText = "Password";
            cPassword.MinimumWidth = 6;
            cPassword.Name = "cPassword";
            // 
            // cStatus
            // 
            cStatus.FillWeight = 130F;
            cStatus.HeaderText = "Status";
            cStatus.MinimumWidth = 6;
            cStatus.Name = "cStatus";
            // 
            // contextMenuStrip1
            // 
            contextMenuStrip1.ImageScalingSize = new System.Drawing.Size(20, 20);
            contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] { importToolStripMenuItem });
            contextMenuStrip1.Name = "contextMenuStrip1";
            contextMenuStrip1.Size = new System.Drawing.Size(124, 28);
            // 
            // importToolStripMenuItem
            // 
            importToolStripMenuItem.Name = "importToolStripMenuItem";
            importToolStripMenuItem.Size = new System.Drawing.Size(123, 24);
            importToolStripMenuItem.Text = "Import";
            importToolStripMenuItem.Click += importToolStripMenuItem_Click;
            // 
            // numThread
            // 
            numThread.Location = new System.Drawing.Point(208, 21);
            numThread.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            numThread.Maximum = new decimal(new int[] { 1000, 0, 0, 0 });
            numThread.Name = "numThread";
            numThread.Size = new System.Drawing.Size(64, 27);
            numThread.TabIndex = 4;
            numThread.Value = new decimal(new int[] { 1, 0, 0, 0 });
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(130, 24);
            label1.Margin = new System.Windows.Forms.Padding(5, 0, 5, 0);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(71, 20);
            label1.TabIndex = 5;
            label1.Text = "Số luồng:";
            // 
            // tbProxy
            // 
            tbProxy.Location = new System.Drawing.Point(774, 21);
            tbProxy.Name = "tbProxy";
            tbProxy.PlaceholderText = "Ip:Port:Username:Password";
            tbProxy.Size = new System.Drawing.Size(287, 27);
            tbProxy.TabIndex = 6;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new System.Drawing.Point(676, 25);
            label2.Margin = new System.Windows.Forms.Padding(5, 0, 5, 0);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(97, 20);
            label2.TabIndex = 7;
            label2.Text = "Proxy bypass:";
            // 
            // cbProxy
            // 
            cbProxy.AutoSize = true;
            cbProxy.Location = new System.Drawing.Point(563, 22);
            cbProxy.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            cbProxy.Name = "cbProxy";
            cbProxy.Size = new System.Drawing.Size(67, 24);
            cbProxy.TabIndex = 8;
            cbProxy.Tag = "";
            cbProxy.Text = "Proxy";
            cbProxy.UseVisualStyleBackColor = true;
            cbProxy.CheckedChanged += cbProxy_CheckedChanged;
            // 
            // tbApiKey
            // 
            tbApiKey.Location = new System.Drawing.Point(1185, 23);
            tbApiKey.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            tbApiKey.Name = "tbApiKey";
            tbApiKey.Size = new System.Drawing.Size(276, 27);
            tbApiKey.TabIndex = 9;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new System.Drawing.Point(1122, 27);
            label3.Margin = new System.Windows.Forms.Padding(5, 0, 5, 0);
            label3.Name = "label3";
            label3.Size = new System.Drawing.Size(60, 20);
            label3.TabIndex = 10;
            label3.Text = "Api TM:";
            // 
            // cbFo4
            // 
            cbFo4.AutoSize = true;
            cbFo4.Location = new System.Drawing.Point(496, 21);
            cbFo4.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            cbFo4.Name = "cbFo4";
            cbFo4.Size = new System.Drawing.Size(57, 24);
            cbFo4.TabIndex = 11;
            cbFo4.Tag = "";
            cbFo4.Text = "FO4";
            cbFo4.UseVisualStyleBackColor = true;
            // 
            // Form1
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(8F, 20F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            ClientSize = new System.Drawing.Size(1514, 684);
            Controls.Add(cbFo4);
            Controls.Add(label3);
            Controls.Add(tbApiKey);
            Controls.Add(cbProxy);
            Controls.Add(dgv);
            Controls.Add(label2);
            Controls.Add(tbProxy);
            Controls.Add(label1);
            Controls.Add(numThread);
            Controls.Add(cbInfo);
            Controls.Add(cbLQ);
            Controls.Add(btnStart);
            Margin = new System.Windows.Forms.Padding(2, 3, 2, 3);
            Name = "Form1";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            Text = "Tool Check Liên Quân By Ngọc Sơn";
            ((System.ComponentModel.ISupportInitialize)dgv).EndInit();
            contextMenuStrip1.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)numThread).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private System.Windows.Forms.Button btnStart;
        private System.Windows.Forms.CheckBox cbLQ;
        private System.Windows.Forms.CheckBox cbInfo;
        private System.Windows.Forms.DataGridView dgv;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem importToolStripMenuItem;
        private System.Windows.Forms.NumericUpDown numThread;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.DataGridViewTextBoxColumn cStt;
        private System.Windows.Forms.DataGridViewTextBoxColumn cUsername;
        private System.Windows.Forms.DataGridViewTextBoxColumn cPassword;
        private System.Windows.Forms.DataGridViewTextBoxColumn cStatus;
        private System.Windows.Forms.TextBox tbProxy;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.CheckBox cbProxy;
        private System.Windows.Forms.TextBox tbApiKey;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.CheckBox cbFo4;
    }
}

